# Run-Anywhere Compute Tasks — Proof of Concept Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working bare-bones implementation of run-anywhere compute tasks per the v0 scope in `docs/superpowers/specs/2026-07-21-run-anywhere-compute-tasks-design.md`: a migratable coroutine type, a global MPMC queue, a reactor idle hook, and shard-affine submit/complete boundaries.

**Architecture:** A new public header `include/seastar/core/compute_task.hh` defines `compute::task<T>` (a coroutine type deliberately NOT derived from `seastar::task`, with a closed awaitable set of exactly one awaitable: `checkpoint()`). A global lock-free MPMC queue of type-erased coroutine handles lives in `src/core/compute_task.cc`. Each reactor gets a second, internal idle handler slot consulted from the idle branch of `reactor::do_run()`; `compute::start()` installs a participant into it on every shard. Completion is marshaled to the submitting shard via `smp::submit_to`.

**Tech Stack:** C++20 coroutines, `boost::lockfree::queue` (already a seastar dependency, used the same way by `alien`), seastar unit-test framework (`SEASTAR_TEST_CASE`).

## Global Constraints

- Minimum C++ version is C++20; use C++20 APIs (project rule from `.claude/CLAUDE.md`).
- Follow existing style; public methods get doxygen comments matching the style of the file they're in.
- No new third-party dependencies. `boost/lockfree/queue.hpp` is already used by `src/core/alien.cc`.
- v0 limitations (by design, do not "fix"): no wakeup of sleeping shards on publish; no parking (every yield goes through the global queue); `T` must be non-void and movable; `compute::stop()` requires all submitted tasks to have completed; no metrics, cancellation, backpressure, or debug tripwires.
- Build/test in `build/release` (exists). `build/debug` is used once at the end for validation (debug builds define `SEASTAR_DEBUG`, which makes `need_preempt()` always return true — this forces a yield at *every* checkpoint, maximally exercising the migration path).
- The public header must NOT include `smp.hh` or `reactor.hh`; cross-shard delivery goes through a small function defined in the `.cc` (keeps compile-time cost down and the header's dependency surface minimal).
- Every commit message ends with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

**If `build/release` turns out not to exist or not to be configured with tests:** run `./configure.py --mode=release` first (takes a few minutes).

---

### Task 1: Global MPMC queue + file scaffolding

**Files:**
- Create: `include/seastar/core/compute_task.hh` (skeleton: internal queue API only)
- Create: `src/core/compute_task.cc`
- Modify: `CMakeLists.txt` (register header + source)
- Create: `tests/unit/compute_task_test.cc`
- Modify: `tests/unit/CMakeLists.txt` (register test)

**Interfaces:**
- Produces (used by Tasks 2-5):
  - `void seastar::compute::internal::queue_push(std::coroutine_handle<> h) noexcept`
  - `std::coroutine_handle<> seastar::compute::internal::queue_try_pop() noexcept` (returns null handle when empty)
  - `bool seastar::compute::internal::queue_empty() noexcept` (relaxed, may be stale)
  - `size_t seastar::compute::internal::queue_size() noexcept` (approximate; for tests)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/compute_task_test.cc`:

```c++
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

#include <coroutine>

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
```

Register the test in `tests/unit/CMakeLists.txt`. The `seastar_add_test` calls are roughly alphabetical; insert next to the `condition_variable` entry (find it with `grep -n "seastar_add_test (co" tests/unit/CMakeLists.txt`):

```cmake
seastar_add_test (compute_task
  SOURCES compute_task_test.cc)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ninja -C build/release tests/unit/compute_task_test 2>&1 | tail -5`
Expected: FAIL — `seastar/core/compute_task.hh: No such file or directory` (after CMake re-runs; ninja re-triggers cmake automatically on CMakeLists.txt change).

- [ ] **Step 3: Write the implementation**

Create `include/seastar/core/compute_task.hh` (same Apache license header as the test file, `Copyright (C) 2026 ScyllaDB Ltd.`):

```c++
#pragma once

#include <coroutine>
#include <cstddef>

/// \file
/// \brief Run-anywhere compute tasks (proof of concept).
///
/// See docs/superpowers/specs/2026-07-21-run-anywhere-compute-tasks-design.md.

namespace seastar::compute {

namespace internal {

/// Push a suspended compute-task coroutine handle onto the global
/// run-anywhere queue. Thread-safe (any reactor thread). After the push the
/// frame may be resumed by any shard; the caller must not touch it again.
void queue_push(std::coroutine_handle<> h) noexcept;

/// Pop one handle from the global queue. Thread-safe. Returns a null handle
/// if the queue is empty.
std::coroutine_handle<> queue_try_pop() noexcept;

/// Cheap (relaxed) emptiness check; may be momentarily stale.
bool queue_empty() noexcept;

/// Approximate queue depth; for tests and future metrics.
size_t queue_size() noexcept;

} // namespace internal

} // namespace seastar::compute
```

Create `src/core/compute_task.cc` (same license header):

```c++
#include <seastar/core/compute_task.hh>
#include <seastar/core/cacheline.hh>
#include <seastar/util/assert.hh>

#include <boost/lockfree/queue.hpp>

#include <atomic>
#include <cstdint>

namespace seastar::compute::internal {

namespace {

// The global many-to-many queue of suspended compute tasks. Producers are
// submitting/yielding shards; consumers are idle shards. Seastar has no
// other multi-consumer structure; boost::lockfree::queue supports MPMC and
// is already used (multi-producer) by alien::message_queue. The explicit
// size counter gives idle shards a one-relaxed-load fast path when the
// queue is empty, following the allocator's xcpu_freelist pattern.
struct compute_queue {
    boost::lockfree::queue<void*> q{128};
    alignas(cache_line_size) std::atomic<int64_t> size{0};
};

compute_queue& the_queue() {
    static compute_queue instance;
    return instance;
}

} // anonymous namespace

void queue_push(std::coroutine_handle<> h) noexcept {
    auto& cq = the_queue();
    // push() only fails on node allocation failure, which is not
    // recoverable here.
    auto ok = cq.q.push(h.address());
    SEASTAR_ASSERT(ok);
    cq.size.fetch_add(1, std::memory_order_release);
}

std::coroutine_handle<> queue_try_pop() noexcept {
    auto& cq = the_queue();
    void* addr = nullptr;
    if (!cq.q.pop(addr)) {
        return {};
    }
    cq.size.fetch_sub(1, std::memory_order_relaxed);
    return std::coroutine_handle<>::from_address(addr);
}

bool queue_empty() noexcept {
    return the_queue().size.load(std::memory_order_relaxed) <= 0;
}

size_t queue_size() noexcept {
    auto s = the_queue().size.load(std::memory_order_relaxed);
    return s < 0 ? 0 : static_cast<size_t>(s);
}

} // namespace seastar::compute::internal
```

Register both files in the root `CMakeLists.txt`:
- Header: the public headers are listed alphabetically (`include/seastar/core/...`). Insert `include/seastar/core/compute_task.hh` immediately before the `include/seastar/core/condition-variable.hh` line (two-space indent, matching neighbors).
- Source: insert `  src/core/compute_task.cc` immediately after the `  src/core/alien.cc` line.

- [ ] **Step 4: Run test to verify it passes**

Run: `ninja -C build/release tests/unit/compute_task_test && ./build/release/tests/unit/compute_task_test -- -c1`
Expected: PASS (`*** No errors detected`).

Note: arguments after `--` go to seastar; `-c1` runs single-shard, adequate here.

- [ ] **Step 5: Commit**

```bash
git add include/seastar/core/compute_task.hh src/core/compute_task.cc CMakeLists.txt tests/unit/compute_task_test.cc tests/unit/CMakeLists.txt
git commit -m "compute: add global run-anywhere task queue

Lock-free MPMC queue of type-erased coroutine handles with a relaxed
size counter for a cheap empty check, per the run-anywhere compute
tasks design doc (v0 scope).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Reactor idle hook

**Files:**
- Modify: `include/seastar/core/reactor.hh` (member near line 350, setters near line 657)
- Modify: `src/core/reactor.cc` (idle branch, near line 3529)
- Test: `tests/unit/compute_task_test.cc` (append)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces (used by Task 3):
  - `void reactor::set_compute_idle_handler(idle_cpu_handler&& handler)` — install; sets the enable flag.
  - `void reactor::clear_compute_idle_handler()` — restore no-op; clears the flag.
  - Semantics: while installed, the handler is invoked from the idle branch before the public `_idle_cpu_handler`, with the same `work_waiting_on_reactor` poll predicate and the same return-value contract (`no_more_work` permits sleep).

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/compute_task_test.cc`:

```c++
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>

#include <chrono>
```

(place includes with the others at the top), then:

```c++
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ninja -C build/release tests/unit/compute_task_test 2>&1 | tail -5`
Expected: FAIL — `no member named 'set_compute_idle_handler' in 'seastar::reactor'`.

- [ ] **Step 3: Write the implementation**

In `include/seastar/core/reactor.hh`, directly after the `_idle_cpu_handler` member (line ~350):

```c++
    /// Internal second idle-handler slot for run-anywhere compute work (see
    /// seastar::compute). Same contract as _idle_cpu_handler; consulted from
    /// the idle branch only when _have_compute_idle_handler is set, keeping
    /// the cost of the unused feature to a single branch on the idle path.
    idle_cpu_handler _compute_idle_handler{ [] (work_waiting_on_reactor) {return idle_cpu_handler_result::no_more_work;} };
    bool _have_compute_idle_handler = false;
```

In `include/seastar/core/reactor.hh`, directly after `set_idle_cpu_handler` (line ~659):

```c++
    /// \cond internal
    /// Install the run-anywhere compute participant (see seastar::compute).
    /// Same contract as set_idle_cpu_handler; a separate slot so the public
    /// idle handler remains available to applications.
    void set_compute_idle_handler(idle_cpu_handler&& handler) {
        _compute_idle_handler = std::move(handler);
        _have_compute_idle_handler = true;
    }
    /// Remove the run-anywhere compute participant.
    void clear_compute_idle_handler() {
        _compute_idle_handler = [] (work_waiting_on_reactor) { return idle_cpu_handler_result::no_more_work; };
        _have_compute_idle_handler = false;
    }
    /// \endcond
```

In `src/core/reactor.cc`, the idle branch currently reads (near line 3529):

```c++
            bool go_to_sleep = true;
            try {
                // we can't run check_for_work(), because that can run tasks in the context
                // of the idle handler which change its state, without the idle handler expecting
                // it.  So run pure_check_for_work() instead.
                auto handler_result = _idle_cpu_handler(pure_check_for_work);
                go_to_sleep = handler_result == idle_cpu_handler_result::no_more_work;
            } catch (...) {
```

Change it to (compute handler first — compute work should get a chance before the shard considers sleeping; `&=` so either handler can veto sleep):

```c++
            bool go_to_sleep = true;
            try {
                // we can't run check_for_work(), because that can run tasks in the context
                // of the idle handler which change its state, without the idle handler expecting
                // it.  So run pure_check_for_work() instead.
                if (_have_compute_idle_handler) {
                    go_to_sleep &= _compute_idle_handler(pure_check_for_work) == idle_cpu_handler_result::no_more_work;
                }
                auto handler_result = _idle_cpu_handler(pure_check_for_work);
                go_to_sleep &= handler_result == idle_cpu_handler_result::no_more_work;
            } catch (...) {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ninja -C build/release tests/unit/compute_task_test && ./build/release/tests/unit/compute_task_test -- -c1`
Expected: PASS, both test cases. (Touching reactor.hh rebuilds much of libseastar; expect a few minutes.)

- [ ] **Step 5: Commit**

```bash
git add include/seastar/core/reactor.hh src/core/reactor.cc tests/unit/compute_task_test.cc
git commit -m "reactor: add internal compute idle-handler slot

A second idle-handler seam consulted from the idle branch, gated on a
bool so the unused feature costs one branch on the idle path and
nothing on the busy path. Keeps the public set_idle_cpu_handler()
available to applications.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `compute::task<T>`, `checkpoint()`, `submit()`, participant, `start()`/`stop()`

**Files:**
- Modify: `include/seastar/core/compute_task.hh` (add the coroutine type and public API)
- Modify: `src/core/compute_task.cc` (add `deliver_on`, participant, `start`/`stop`)
- Test: `tests/unit/compute_task_test.cc` (append)

**Interfaces:**
- Consumes: Task 1's `queue_push`/`queue_try_pop`/`queue_empty`; Task 2's `set_compute_idle_handler`/`clear_compute_idle_handler`.
- Produces (used by Tasks 4-5):
  - `template <typename T> class compute::task` — coroutine return type; `T` non-void, movable.
  - `compute::checkpoint_t compute::checkpoint() noexcept` — the only awaitable usable inside a `compute::task`.
  - `template <typename T> future<T> compute::submit(compute::task<T> t)` — reactor thread only; future resolves on the calling shard.
  - `future<> compute::start()` / `future<> compute::stop()` — install/remove the participant on all shards (call from one shard, typically 0). `stop()` requires all submitted tasks to have completed.
  - `void compute::internal::deliver_on(shard_id home, noncopyable_function<void ()> f) noexcept` — fire-and-forget cross-shard delivery (in the `.cc`, so the header stays free of `smp.hh`).

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/compute_task_test.cc` (add `#include <seastar/core/smp.hh>` to the includes):

```c++
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ninja -C build/release tests/unit/compute_task_test 2>&1 | tail -5`
Expected: FAIL — `no member named 'task' in namespace 'seastar::compute'` (or similar).

- [ ] **Step 3: Write the implementation — header**

Replace the body of `include/seastar/core/compute_task.hh` below the license header with:

```c++
#pragma once

#include <seastar/core/future.hh>
#include <seastar/core/preempt.hh>
#include <seastar/core/shard_id.hh>
#include <seastar/util/assert.hh>
#include <seastar/util/noncopyable_function.hh>

#include <coroutine>
#include <cstddef>
#include <exception>
#include <optional>
#include <utility>

/// \file
/// \brief Run-anywhere compute tasks (proof of concept).
///
/// A compute::task<T> is a coroutine with no core affinity: it is executed,
/// checkpoint-to-checkpoint, by whichever shard has spare CPU, strictly below
/// all normal seastar work. It may not touch shard-affine seastar machinery;
/// the only thing it can co_await is compute::checkpoint(). Submit and
/// completion are shard-affine: submit() returns an ordinary future that
/// resolves on the submitting shard.
///
/// v0 limitations: sleeping shards are not woken for new compute work; T must
/// be non-void and movable; stop() requires all submitted tasks to have
/// completed. See docs/superpowers/specs/2026-07-21-run-anywhere-compute-tasks-design.md.

namespace seastar::compute {

namespace internal {

/// Push a suspended compute-task coroutine handle onto the global
/// run-anywhere queue. Thread-safe (any reactor thread). After the push the
/// frame may be resumed by any shard; the caller must not touch it again.
void queue_push(std::coroutine_handle<> h) noexcept;

/// Pop one handle from the global queue. Thread-safe. Returns a null handle
/// if the queue is empty.
std::coroutine_handle<> queue_try_pop() noexcept;

/// Cheap (relaxed) emptiness check; may be momentarily stale.
bool queue_empty() noexcept;

/// Approximate queue depth; for tests and future metrics.
size_t queue_size() noexcept;

/// Run \c f on shard \c home, fire-and-forget. Must be called from a reactor
/// thread. Defined in compute_task.cc so this header need not pull in smp.hh.
void deliver_on(shard_id home, noncopyable_function<void ()> f) noexcept;

/// Home-shard state of one submitted task: created by submit() on the
/// submitting shard, fulfilled and deleted there by deliver_on().
template <typename T>
struct completion {
    promise<T> pr;
};

} // namespace internal

/// Tag type returned by \ref checkpoint().
struct checkpoint_t {};

/// Cooperative scheduling point; the only thing a compute task can co_await.
/// While the running shard remains idle this never suspends; when the shard
/// is preempted, the task suspends and is re-queued on the global run-anywhere
/// queue, and may resume on a different shard.
inline checkpoint_t checkpoint() noexcept {
    return {};
}

/// \cond internal
struct checkpoint_awaiter {
    bool await_ready() const noexcept {
        return !need_preempt();
    }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        // Publish-and-forget: after this push another shard may resume (and
        // even finish and destroy) the frame concurrently. This must be the
        // last touch of anything reachable from `h` — including this awaiter
        // object, which lives inside the frame.
        internal::queue_push(h);
    }
    void await_resume() const noexcept {}
};
/// \endcond

/// A run-anywhere compute task. Create by writing a coroutine returning
/// compute::task<T>; nothing runs until the task is passed to submit().
/// Move-only; destroying an unsubmitted task destroys the coroutine frame.
template <typename T>
class task {
public:
    class promise_type;
    using handle_type = std::coroutine_handle<promise_type>;
private:
    handle_type _h;
    explicit task(handle_type h) noexcept : _h(h) {}
public:
    task(task&& o) noexcept : _h(std::exchange(o._h, {})) {}
    task(const task&) = delete;
    task& operator=(task&&) = delete;
    task& operator=(const task&) = delete;
    ~task() {
        if (_h) {
            _h.destroy();
        }
    }
    template <typename U>
    friend future<U> submit(task<U> t);
};

template <typename T>
class task<T>::promise_type {
    internal::completion<T>* _completion = nullptr;
    shard_id _home_shard = 0;
    std::optional<T> _result;
    std::exception_ptr _ex;

    struct final_awaiter {
        bool await_ready() const noexcept { return false; }
        void await_suspend(handle_type h) noexcept {
            // The task is finished, on whatever shard we happen to be. Move
            // everything out of the frame, destroy the frame (cross-shard
            // frees are supported by the allocator), then deliver the result
            // to the home shard, where the promise lives and where it must
            // be fulfilled.
            auto& pr = h.promise();
            auto* completion = pr._completion;
            auto home = pr._home_shard;
            auto result = std::move(pr._result);
            auto ex = std::move(pr._ex);
            h.destroy();
            internal::deliver_on(home, [completion, result = std::move(result), ex = std::move(ex)] () mutable {
                if (ex) {
                    completion->pr.set_exception(std::move(ex));
                } else {
                    completion->pr.set_value(std::move(*result));
                }
                delete completion;
            });
        }
        void await_resume() noexcept {}
    };

public:
    task<T> get_return_object() noexcept {
        return task<T>(handle_type::from_promise(*this));
    }
    // Lazy: the body first runs when an idle shard pops the handle.
    std::suspend_always initial_suspend() noexcept { return {}; }
    final_awaiter final_suspend() noexcept { return {}; }
    void return_value(T v) {
        _result.emplace(std::move(v));
    }
    void unhandled_exception() noexcept {
        _ex = std::current_exception();
    }
    // The closed awaitable set: checkpoints only. Because an await_transform
    // is defined, co_await on anything else — a seastar future, most
    // importantly — does not compile inside a compute task.
    checkpoint_awaiter await_transform(checkpoint_t) noexcept {
        return {};
    }

    template <typename U>
    friend future<U> submit(task<U> t);
};

/// Submit a compute task for execution. Must be called on a reactor thread.
/// The returned future resolves on the calling shard when the task completes
/// (with its co_return value, or with the exception it exited with); the
/// future's continuations are ordinary shard-local continuations.
///
/// compute::start() must have been called, otherwise no shard will ever run
/// the task.
template <typename T>
future<T> submit(task<T> t) {
    auto h = std::exchange(t._h, {});
    SEASTAR_ASSERT(h && !h.done());
    auto& pr = h.promise();
    auto completion = std::make_unique<internal::completion<T>>();
    auto fut = completion->pr.get_future();
    pr._home_shard = this_shard_id();
    pr._completion = completion.release();
    internal::queue_push(h);
    return fut;
}

/// Install the run-anywhere participant on every shard. Call once, from one
/// shard, before the first submit().
future<> start();

/// Remove the participant from every shard. All submitted tasks must have
/// completed (v0 limitation: still-queued tasks would leak and their futures
/// would never resolve).
future<> stop();

} // namespace seastar::compute
```

- [ ] **Step 4: Write the implementation — source**

In `src/core/compute_task.cc`, add to the includes:

```c++
#include <seastar/core/reactor.hh>
#include <seastar/core/smp.hh>
```

and append after the queue functions (inside `namespace seastar::compute`, with the queue internals staying in `namespace internal`):

```c++
void deliver_on(shard_id home, noncopyable_function<void ()> f) noexcept {
    // set_value/set_exception do not throw; a failure of the submission
    // itself (e.g. at shutdown) is swallowed — v0 has no cancellation story.
    (void)smp::submit_to(home, std::move(f)).handle_exception([] (std::exception_ptr) {});
}

namespace {

// The per-shard participant: runs compute work from the idle branch. Pops
// and resumes queued tasks until the reactor has real work (poll) or wants
// a housekeeping iteration (need_preempt); resuming leaves the frame either
// completed (destroyed) or republished on the queue, so `h` is never touched
// after resume().
idle_cpu_handler_result run_some(work_waiting_on_reactor poll) {
    if (internal::queue_empty()) {
        return idle_cpu_handler_result::no_more_work;
    }
    while (!poll()) {
        auto h = internal::queue_try_pop();
        if (!h) {
            return idle_cpu_handler_result::no_more_work;
        }
        h.resume();
        if (need_preempt()) {
            // Let the main loop run one housekeeping iteration (pollers,
            // clocks, preemption-monitor reset). If the shard is still idle
            // it lands right back here.
            return idle_cpu_handler_result::interrupted_by_higher_priority_task;
        }
    }
    return idle_cpu_handler_result::interrupted_by_higher_priority_task;
}

} // anonymous namespace

future<> start() {
    return smp::invoke_on_all([] {
        engine().set_compute_idle_handler(run_some);
    });
}

future<> stop() {
    return smp::invoke_on_all([] {
        engine().clear_compute_idle_handler();
    });
}

} // namespace seastar::compute
```

Note the namespace restructuring this implies: the file now has `namespace seastar::compute { namespace internal { ...queue + deliver_on... } namespace { run_some } start/stop }`. Keep `deliver_on` inside `internal`, `run_some` in the anonymous namespace, `start`/`stop` in `seastar::compute`.

- [ ] **Step 5: Run test to verify it passes**

Run: `ninja -C build/release tests/unit/compute_task_test && ./build/release/tests/unit/compute_task_test`
Expected: PASS, all four test cases (default smp; the shard-affinity test needs ≥2 shards, which the test runner default provides — if running the binary directly on a 1-cpu box, `smp::count - 1` degenerates to shard 0 and the test still passes trivially).

- [ ] **Step 6: Commit**

```bash
git add include/seastar/core/compute_task.hh src/core/compute_task.cc tests/unit/compute_task_test.cc
git commit -m "compute: add run-anywhere compute task type (proof of concept)

compute::task<T> is a coroutine with no core affinity, executed
checkpoint-to-checkpoint by whichever shard has spare CPU via the
reactor's compute idle handler, strictly below normal seastar work.
The closed awaitable set (checkpoint() only) makes shard-affine
seastar machinery unreachable at compile time. submit()/completion
are shard-affine: the returned future resolves on the submitting
shard, thread_pool-style, via smp::submit_to.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Exception marshaling

**Files:**
- Test: `tests/unit/compute_task_test.cc` (append)
- Possibly fix: `include/seastar/core/compute_task.hh` (only if the test exposes a defect)

**Interfaces:**
- Consumes: Task 3's `submit`, `checkpoint`, `start`/`stop`.
- Produces: nothing new; validates the `unhandled_exception` → `set_exception` path.

- [ ] **Step 1: Write the failing-or-passing test**

Append to `tests/unit/compute_task_test.cc` (add `#include <stdexcept>`):

```c++
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
```

- [ ] **Step 2: Run the test**

Run: `ninja -C build/release tests/unit/compute_task_test && ./build/release/tests/unit/compute_task_test`
Expected: PASS (the path was implemented in Task 3). If it fails, the defect is in `final_awaiter::await_suspend` or `unhandled_exception` — fix there, not in the test.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/compute_task_test.cc
git commit -m "compute: test exception marshaling to the home shard

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Concurrency and migration coverage

**Files:**
- Test: `tests/unit/compute_task_test.cc` (append)

**Interfaces:**
- Consumes: Task 3's full API.
- Produces: nothing new; validates many-task operation and cross-shard frame movement.

- [ ] **Step 1: Write the tests**

Append to `tests/unit/compute_task_test.cc` (add `#include <set>` and `#include <vector>`):

```c++
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
```

- [ ] **Step 2: Run the tests, including multi-shard**

Run: `ninja -C build/release tests/unit/compute_task_test && ./build/release/tests/unit/compute_task_test -- -c2`
Expected: PASS, all seven test cases.

Then run through the harness: `./test.py --mode release --name compute_task`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/compute_task_test.cc
git commit -m "compute: test many-task completion and cross-shard migration

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Debug-mode validation and PR update

**Files:**
- Possibly fix: any file, if debug mode exposes a defect
- Modify: `docs/superpowers/specs/2026-07-21-run-anywhere-compute-tasks-design.md` (status line)

**Interfaces:** none new.

- [ ] **Step 1: Build and run the test in debug mode**

Run: `ninja -C build/debug tests/unit/compute_task_test && ./test.py --mode debug --name compute_task`
Expected: PASS. Debug mode makes `need_preempt()` return true unconditionally, so every checkpoint suspends and republishes to the global queue — the migration path runs at every single checkpoint, and the debug allocator + `SEASTAR_DEBUG_PROMISE` shard tripwire audit the memory and promise discipline. This is the strongest validation the PoC gets; investigate any failure rather than weakening the test.

- [ ] **Step 2: Update the design doc status**

In `docs/superpowers/specs/2026-07-21-run-anywhere-compute-tasks-design.md`, change the status line:

```markdown
Date: 2026-07-21 · Status: v0 proof of concept implemented (see docs/superpowers/plans/2026-07-23-run-anywhere-compute-poc.md) · Scope: design + PoC
```

- [ ] **Step 3: Commit and push to the PR**

```bash
git add docs/superpowers/
git commit -m "docs: mark run-anywhere design as v0-implemented; add PoC plan

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
git push
```

---

## Self-Review Notes

- **Spec coverage** (v0 scope section): coroutine type ✔ (Task 3), boundary-crossing semantics ✔ (Task 3 submit/deliver_on + Tasks 4-5 tests), global MPMC queue ✔ (Task 1), reactor idle hook ✔ (Task 2), explicit opt-in start/stop ✔ (Task 3). Deferred items (wakeup, parking, metrics, tripwires, backpressure, cancellation) intentionally absent.
- **Known v0 behaviors, not bugs:** a fully slept shard won't notice new compute work (submitting shard picks it up on its own idle branch); every yield round-trips the global queue; `compute::stop()` with queued tasks leaks them.
- **Type consistency:** `queue_push/queue_try_pop/queue_empty/queue_size`, `set_compute_idle_handler/clear_compute_idle_handler`, `checkpoint_t/checkpoint()`, `submit`, `start/stop`, `deliver_on`, `completion<T>` — names match across all tasks.
