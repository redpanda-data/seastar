/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2026 ScyllaDB Ltd.
 */

#include <seastar/testing/test_case.hh>
#include <seastar/core/compute_task.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/smp.hh>
#include <seastar/coroutine/maybe_yield.hh>

#include <chrono>
#include <coroutine>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

using namespace seastar;

SEASTAR_TEST_CASE(compute_queue_push_pop_roundtrip) {
    BOOST_REQUIRE(compute::internal::queue_empty());
    BOOST_REQUIRE(!compute::internal::queue_try_pop());

    std::coroutine_handle<> h = std::noop_coroutine();
    compute::internal::queue_push(h);
    BOOST_REQUIRE(!compute::internal::queue_empty());
    BOOST_REQUIRE_EQUAL(compute::internal::queue_size(), 1u);

    auto popped = compute::internal::queue_try_pop();
    BOOST_REQUIRE(popped);
    BOOST_REQUIRE(popped.address() == h.address());
    BOOST_REQUIRE(compute::internal::queue_empty());
    BOOST_REQUIRE(!compute::internal::queue_try_pop());
    return make_ready_future<>();
}

SEASTAR_TEST_CASE(compute_idle_handler_runs_when_idle) {
    unsigned invocations = 0;
    engine().set_compute_idle_handler([&invocations] (work_waiting_on_reactor) {
        ++invocations;
        return idle_cpu_handler_result::no_more_work;
    });
    // Sleeping makes this shard idle; the idle branch must consult the
    // compute handler at least once before the reactor goes to sleep.
    co_await seastar::sleep(std::chrono::milliseconds(100));
    engine().clear_compute_idle_handler();
    BOOST_REQUIRE_GT(invocations, 0u);
}

namespace {

compute::task<uint64_t> sum_range(uint64_t n) {
    uint64_t acc = 0;
    for (uint64_t i = 1; i <= n; ++i) {
        acc += i;
        co_await compute::checkpoint();
    }
    co_return acc;
}

} // anonymous namespace

SEASTAR_TEST_CASE(compute_submit_completes_with_result) {
    co_await compute::start();
    auto v = co_await compute::submit(sum_range(100));
    BOOST_REQUIRE_EQUAL(v, 5050u);
    co_await compute::stop();
}

SEASTAR_TEST_CASE(compute_completion_is_shard_affine) {
    co_await compute::start();
    // Submit from the highest shard; the continuation must run there.
    co_await smp::submit_to(smp::count - 1, [] () -> future<> {
        auto submitted_on = this_shard_id();
        auto v = co_await compute::submit(sum_range(10));
        BOOST_REQUIRE_EQUAL(v, 55u);
        BOOST_REQUIRE_EQUAL(this_shard_id(), submitted_on);
    });
    co_await compute::stop();
}

namespace {

compute::task<int> throws_midway() {
    co_await compute::checkpoint();
    throw std::runtime_error("boom");
    co_return 0; // unreachable; satisfies the return_value requirement
}

} // anonymous namespace

SEASTAR_TEST_CASE(compute_exception_marshals_home) {
    co_await compute::start();
    auto submitted_on = this_shard_id();
    auto fut = compute::submit(throws_midway());
    BOOST_REQUIRE_THROW(co_await std::move(fut), std::runtime_error);
    BOOST_REQUIRE_EQUAL(this_shard_id(), submitted_on);
    co_await compute::stop();
}

SEASTAR_TEST_CASE(compute_many_tasks_complete_correctly) {
    co_await compute::start();
    constexpr int n_tasks = 50;
    std::vector<future<uint64_t>> futs;
    futs.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        futs.push_back(compute::submit(sum_range(50 + i)));
    }
    for (int i = 0; i < n_tasks; ++i) {
        uint64_t n = 50 + i;
        BOOST_REQUIRE_EQUAL(co_await std::move(futs[i]), n * (n + 1) / 2);
    }
    co_await compute::stop();
}

namespace {

// Collects the shards the task observes itself running on. Reading
// this_shard_id() is a plain thread-local read, safe within a resume
// segment; the std::set lives in the frame and its nodes may be allocated
// on several shards and freed on the home shard — exercising exactly the
// cross-shard memory path the design relies on.
compute::task<std::set<unsigned>> observe_shards(int iters) {
    std::set<unsigned> shards;
    for (int i = 0; i < iters; ++i) {
        shards.insert(this_shard_id());
        co_await compute::checkpoint();
    }
    co_return shards;
}

} // anonymous namespace

SEASTAR_TEST_CASE(compute_task_survives_migration) {
    co_await compute::start();
    auto shards = co_await compute::submit(observe_shards(200));
    // Migration is timing-dependent, so only completion and state integrity
    // are asserted; the shard count is informational.
    BOOST_REQUIRE_GE(shards.size(), 1u);
    BOOST_TEST_MESSAGE(seastar::format("task observed {} distinct shard(s)", shards.size()));
    co_await compute::stop();
}

namespace {

// Keeps a shard saturated with runnable foreground work: spin a slice, then
// yield to the scheduler only when the quota expires, so the shard's task
// queue is never empty and its idle branch is (almost) never reached.
future<> burn_cpu_for(std::chrono::steady_clock::duration d) {
    auto end = std::chrono::steady_clock::now() + d;
    while (std::chrono::steady_clock::now() < end) {
        auto spin_end = std::chrono::steady_clock::now() + std::chrono::microseconds(100);
        while (std::chrono::steady_clock::now() < spin_end) {
            // burn
        }
        co_await coroutine::maybe_yield();
    }
}

// Counts, per shard, how many compute iterations executed there. Each
// iteration burns ~10us so the counts reflect real CPU placement.
compute::task<std::map<unsigned, uint64_t>> count_executions(int iters) {
    std::map<unsigned, uint64_t> counts;
    for (int i = 0; i < iters; ++i) {
        ++counts[this_shard_id()];
        auto spin_end = std::chrono::steady_clock::now() + std::chrono::microseconds(10);
        while (std::chrono::steady_clock::now() < spin_end) {
            // burn
        }
        co_await compute::checkpoint();
    }
    co_return counts;
}

} // anonymous namespace

SEASTAR_TEST_CASE(compute_avoids_busy_shards) {
    if (smp::count < 4) {
        BOOST_TEST_MESSAGE("compute_avoids_busy_shards requires 4 shards (run with -c4); skipping");
        co_return;
    }
    co_await compute::start();
    // Saturate shards 2 and 3 with foreground work for the whole test.
    auto busy2 = smp::submit_to(2, [] { return burn_cpu_for(std::chrono::seconds(2)); });
    auto busy3 = smp::submit_to(3, [] { return burn_cpu_for(std::chrono::seconds(2)); });
    // Let the busy loops saturate their shards before submitting compute work.
    co_await seastar::sleep(std::chrono::milliseconds(100));

    constexpr int n_tasks = 4;
    constexpr int iters = 1000;
    std::vector<future<std::map<unsigned, uint64_t>>> futs;
    futs.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        futs.push_back(compute::submit(count_executions(iters)));
    }

    uint64_t total = 0;
    uint64_t on_busy = 0;
    for (auto& f : futs) {
        auto counts = co_await std::move(f);
        for (auto& [shard, n] : counts) {
            total += n;
            if (shard >= 2) {
                on_busy += n;
            }
        }
    }
    BOOST_REQUIRE_EQUAL(total, uint64_t(n_tasks) * iters);
    BOOST_TEST_MESSAGE(seastar::format("{} of {} compute iterations ran on the busy shards", on_busy, total));
    // "Statistically almost none": allow up to 1% for edge windows around the
    // busy loops' start-up.
    BOOST_REQUIRE_LE(on_busy, total / 100);
    co_await std::move(busy2);
    co_await std::move(busy3);
    co_await compute::stop();
}
