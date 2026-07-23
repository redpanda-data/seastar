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

#include <chrono>
#include <coroutine>
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
