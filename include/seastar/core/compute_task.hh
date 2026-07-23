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
