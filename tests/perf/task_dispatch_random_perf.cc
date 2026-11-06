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

// Measures task dispatch when the next task follows a given sequence,
// predictable or random. Exactly one task is queued at a time.
//
// There are 16 coroutine instances and 16 continuation instances, and each
// waits on its own promise. Each task, when it runs, re-arms its promise and
// fulfills the promise the sequence names next. Fulfilling a promise is the
// same code for every task, so nothing about the next task's kind or type
// reaches the branch history before it is dispatched.
//
// The coroutines are 16 functions sharing 4 return types, so 4 per promise
// type: with a vtable, a coroutine takes one call through the promise type's
// run_and_dispose(), with 4 targets, and then one through the frame's resume
// function, with 4 targets per call site.

#include <seastar/testing/perf_tests.hh>

#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/when_all.hh>

#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <utility>
#include <vector>

using namespace seastar;

namespace {

constexpr int instances = 16;      // of each kind
constexpr int return_types = 4;
// Long enough that a branch predictor cannot learn the random sequences.
constexpr size_t sequence_length = size_t(1) << 16;
constexpr size_t steps = 20000;

struct driver {
    std::vector<promise<>*> sequence;
    size_t pos = 0;
    size_t left = 0;
    bool stopping = false;
    // Coroutines wait on [0, instances), continuations on [instances, 2 * instances).
    std::array<promise<>, 2 * instances> armed;
    std::optional<promise<>> done;
};

thread_local driver* drv;

// Wakes the task the sequence names next, or ends the run.
void step() noexcept {
    if (--drv->left == 0) {
        drv->done->set_value();
        return;
    }
    drv->sequence[drv->pos++ & (sequence_length - 1)]->set_value();
}

future<> arm(int slot) {
    return (drv->armed[slot] = promise<>()).get_future();
}

template <int R>
struct ret { int value; };

template <int F>
future<ret<F % return_types>> coroutine_worker(int slot) {
    auto f = arm(slot);
    for (;;) {
        co_await std::move(f);
        if (drv->stopping) {
            co_return ret<F % return_types>{F};
        }
        perf_tests::do_not_optimize(F);
        f = arm(slot);
        step();
    }
}

template <int F>
void arm_continuation(int slot) {
    (void)arm(slot).then([slot] {
        if (drv->stopping) {
            return;
        }
        perf_tests::do_not_optimize(F);
        arm_continuation<F>(slot);
        step();
    });
}

// Distinct: instance i runs function i. Otherwise every instance of a kind
// runs function 0, so a kind always dispatches to the same target.
template <bool Distinct, int... I>
future<> run_sequence(std::integer_sequence<int, I...>, driver& d) {
    drv = &d;
    d.stopping = false;
    d.left = steps;
    d.done.emplace();
    auto workers = when_all(coroutine_worker<Distinct ? I : 0>(I)...);   // each runs to its first co_await
    (arm_continuation<Distinct ? I : 0>(instances + I), ...);
    auto done = d.done->get_future();
    perf_tests::start_measuring_time();
    step();
    co_await std::move(done);
    perf_tests::stop_measuring_time();
    d.stopping = true;
    for (auto& p : d.armed) {
        p.set_value();
    }
    co_await std::move(workers);
}

enum class kind_pattern { coroutines, continuations, alternate, random };
enum class order { cycle, random };

// Slot indices; never the same slot twice in a row, since the running task
// cannot also be waiting.
std::vector<int> make_slots(kind_pattern kinds, order ord) {
    std::mt19937 rng(12345);
    std::vector<int> s(sequence_length);
    int prev = -1;
    for (size_t i = 0; i < s.size(); ++i) {
        int slot;
        do {
            bool coroutine = kinds == kind_pattern::coroutines
                    || (kinds == kind_pattern::alternate && i % 2 == 0)
                    || (kinds == kind_pattern::random && (rng() & 1));
            int instance = ord == order::cycle ? int((kinds == kind_pattern::alternate ? i / 2 : i) % instances)
                    : int(rng() % instances);
            slot = (coroutine ? 0 : instances) + instance;
        } while (slot == prev);
        s[i] = prev = slot;
    }
    return s;
}

}

struct task_dispatch_random {
    driver d;
    // Runs continue through the sequence where the previous run stopped.
    template <bool Distinct = true>
    future<size_t> measure(kind_pattern kinds, order ord) {
        if (d.sequence.empty() || _kinds != kinds || _ord != ord) {
            d.sequence.clear();
            for (int slot : make_slots(kinds, ord)) {
                d.sequence.push_back(&d.armed[slot]);
            }
            d.pos = 0;
            _kinds = kinds;
            _ord = ord;
        }
        co_await run_sequence<Distinct>(std::make_integer_sequence<int, instances>{}, d);
        co_return steps;
    }
private:
    kind_pattern _kinds{};
    order _ord{};
};

// Only coroutines, or only continuations: in a fixed cycle, or random.
PERF_TEST_CN(task_dispatch_random, coroutine_cycle) { return measure(kind_pattern::coroutines, order::cycle); }
PERF_TEST_CN(task_dispatch_random, coroutine_random) { return measure(kind_pattern::coroutines, order::random); }
PERF_TEST_CN(task_dispatch_random, continuation_cycle) { return measure(kind_pattern::continuations, order::cycle); }
PERF_TEST_CN(task_dispatch_random, continuation_random) { return measure(kind_pattern::continuations, order::random); }

// Half coroutines and half continuations.
// Kinds alternate, instances cycle: everything predictable.
PERF_TEST_CN(task_dispatch_random, mix_alternate_cycle) { return measure(kind_pattern::alternate, order::cycle); }
// Kinds alternate, instances random.
PERF_TEST_CN(task_dispatch_random, mix_alternate_random) { return measure(kind_pattern::alternate, order::random); }
// Kinds random, but every instance of a kind runs the same function: only
// the kind is unpredictable.
PERF_TEST_CN(task_dispatch_random, mix_random_fixed) { return measure<false>(kind_pattern::random, order::random); }
// Kinds and instances random.
PERF_TEST_CN(task_dispatch_random, mix_random_random) { return measure(kind_pattern::random, order::random); }
