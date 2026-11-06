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
 * Copyright (C) 2026-present Redpanda Data
 */

// Measures the reactor's task dispatch: every step of every test goes through
// the task queue. Each test runs `types` distinct task types at once, so
// consecutive dispatches go to different targets, as in a real reactor.

#include <seastar/testing/perf_tests.hh>

#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/task.hh>
#include <seastar/core/when_all.hh>
#include <seastar/util/later.hh>

#include <coroutine>
#include <utility>

using namespace seastar;

namespace {

constexpr size_t steps = 1000;

// Suspends and puts the coroutine straight back on the task queue, so each
// co_await is exactly one task dispatch.
struct requeue {
    bool await_ready() const noexcept { return false; }
    template <typename T>
    void await_suspend(std::coroutine_handle<T> h) noexcept { schedule(&h.promise()); }
    void await_resume() const noexcept {}
};

template <int I>
future<> coroutine_loop() {
    for (size_t i = 0; i < steps; ++i) {
        co_await requeue{};
        perf_tests::do_not_optimize(I);
    }
}

// Each step is three dispatches: the lambda_task behind yield(), the then()
// continuation, and the repeater.
template <int I>
future<> then_loop() {
    static thread_local size_t left;
    left = steps;
    return repeat([] {
        return yield().then([] {
            perf_tests::do_not_optimize(I);
            return stop_iteration(--left == 0);
        });
    });
}

// A task type written directly against the task interface, which reschedules
// itself: one dispatch per step.
template <int I>
class requeue_task final : public task {
    size_t _left = steps;
    promise<> _done;
public:
    future<> done() { return _done.get_future(); }
    void run_and_dispose() noexcept override {
        perf_tests::do_not_optimize(I);
        if (--_left) {
            schedule(this);
        } else {
            _done.set_value();
            delete this;
        }
    }
    task* waiting_task() noexcept override { return nullptr; }
};

template <int I>
future<> task_loop() {
    auto* t = new requeue_task<I>();
    auto f = t->done();
    schedule(t);
    return f;
}

template <int... I, typename Start>
future<> run_all(std::integer_sequence<int, I...>, Start start) {
    co_await when_all(start.template operator()<I>()...);
}

template <int Types>
future<size_t> run_coroutines() {
    co_await run_all(std::make_integer_sequence<int, Types>{}, [] <int I> () { return coroutine_loop<I>(); });
    co_return Types * steps;
}

template <int Types>
future<size_t> run_thens() {
    co_await run_all(std::make_integer_sequence<int, Types>{}, [] <int I> () { return then_loop<I>(); });
    co_return Types * steps;
}

template <int Types>
future<size_t> run_tasks() {
    co_await run_all(std::make_integer_sequence<int, Types>{}, [] <int I> () { return task_loop<I>(); });
    co_return Types * steps;
}

}

struct task_dispatch {};

PERF_TEST_CN(task_dispatch, coroutine_1) { return run_coroutines<1>(); }
PERF_TEST_CN(task_dispatch, coroutine_8) { return run_coroutines<8>(); }
PERF_TEST_CN(task_dispatch, coroutine_64) { return run_coroutines<64>(); }

PERF_TEST_CN(task_dispatch, then_1) { return run_thens<1>(); }
PERF_TEST_CN(task_dispatch, then_8) { return run_thens<8>(); }
PERF_TEST_CN(task_dispatch, then_64) { return run_thens<64>(); }

PERF_TEST_CN(task_dispatch, virtual_1) { return run_tasks<1>(); }
PERF_TEST_CN(task_dispatch, virtual_8) { return run_tasks<8>(); }
PERF_TEST_CN(task_dispatch, virtual_64) { return run_tasks<64>(); }

// Coroutines and continuations interleaved, 32 types of each.
PERF_TEST_CN(task_dispatch, mixed_64) {
    auto [c, t] = co_await when_all_succeed(run_coroutines<32>(), run_thens<32>());
    co_return c + t;
}
