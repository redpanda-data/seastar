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
 * Copyright (C) 2015 Cloudius Systems, Ltd.
 */

#pragma once

#include <seastar/core/scheduling.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/util/backtrace.hh>

#include <utility>

namespace seastar {

/// \brief Base class for user-defined task context.
///
/// Derive from this to attach application-specific context (e.g.,
/// tracing) that propagates automatically through the task chain.
/// Use \ref with_context to scope a context to a function call.
///
/// Context does NOT propagate across shards (smp::submit_to) since
/// lw_shared_ptr is not thread-safe.
///
/// Guarded by the SEASTAR_TASK_CONTEXT compile flag.
struct task_context : enable_lw_shared_from_this<task_context> {
    virtual ~task_context() = default;
};

namespace internal {
#ifdef SEASTAR_TASK_CONTEXT
task_context*& current_task_context_ref() noexcept;
lw_shared_ptr<task_context> inherit_task_context() noexcept;
#endif
} // namespace internal

class task {
protected:
    scheduling_group _sg;
private:
#ifdef SEASTAR_TASK_BACKTRACE
    shared_backtrace _bt;
#endif
#ifdef SEASTAR_TASK_CONTEXT
    lw_shared_ptr<task_context> _context;
#endif
protected:
    // Task destruction is performed by run_and_dispose() via a concrete type,
    // so no need for a virtual destructor here. Derived classes that implement
    // run_and_dispose() should be declared final to avoid losing concrete type
    // information via inheritance.
    ~task() = default;

    scheduling_group set_scheduling_group(scheduling_group new_sg) noexcept{
        return std::exchange(_sg, new_sg);
    }
public:
    explicit task(scheduling_group sg = current_scheduling_group()) noexcept
        : _sg(sg)
#ifdef SEASTAR_TASK_CONTEXT
        , _context(internal::inherit_task_context())
#endif
    {}

    /// Tag type to construct a task without inheriting context.
    /// Used by work_item (cross-shard) to avoid a wasted
    /// inherit-then-clear cycle.
    struct no_context_tag {};
    explicit task(scheduling_group sg, no_context_tag) noexcept : _sg(sg) {}
    virtual void run_and_dispose() noexcept = 0;
    /// Returns the next task which is waiting for this task to complete execution, or nullptr.
    virtual task* waiting_task() noexcept = 0;
    scheduling_group group() const { return _sg; }
#ifdef SEASTAR_TASK_BACKTRACE
    void make_backtrace() noexcept;
    shared_backtrace get_backtrace() const { return _bt; }
#else
    void make_backtrace() noexcept {}
    shared_backtrace get_backtrace() const { return {}; }
#endif

#ifdef SEASTAR_TASK_CONTEXT
    task_context* context_ptr() const noexcept { return _context.get(); }
    void set_context(lw_shared_ptr<task_context> ctx) noexcept {
        _context = std::move(ctx);
    }
#else
    task_context* context_ptr() const noexcept { return nullptr; }
    void set_context(lw_shared_ptr<task_context>) noexcept {}
#endif
};


void schedule(task* t) noexcept;
void schedule_checked(task* t) noexcept;
void schedule_urgent(task* t) noexcept;

namespace internal {
#ifdef SEASTAR_TASK_CONTEXT
#ifndef SEASTAR_BUILD_SHARED_LIBS
inline task_context*& current_task_context_ref() noexcept {
    static thread_local task_context* ptr = nullptr;
    return ptr;
}
#endif

inline lw_shared_ptr<task_context> inherit_task_context() noexcept {
    auto* p = current_task_context_ref();
    if (__builtin_expect(p != nullptr, false)) {
        return p->shared_from_this();
    }
    return {};
}
#endif
} // namespace internal

/// Returns the current task context, or nullptr if none is set.
#ifdef SEASTAR_TASK_CONTEXT
inline task_context* current_task_context() noexcept {
    return internal::current_task_context_ref();
}
/// Set the current task context (TLS). Prefer \ref with_context to
/// scope a context to a function call; this setter is primarily for
/// building custom RAII or awaitable helpers on top of the primitive.
inline void set_current_task_context(task_context* ctx) noexcept {
    internal::current_task_context_ref() = ctx;
}
#else
inline task_context* current_task_context() noexcept { return nullptr; }
inline void set_current_task_context(task_context*) noexcept {}
#endif

}
