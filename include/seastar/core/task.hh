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
#include <seastar/util/assert.hh>
#include <seastar/util/backtrace.hh>

#include <coroutine>
#include <cstdlib>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <source_location>

namespace seastar {

class task;
class runnable_task;
class coroutine_task;

/// What diagnostics need from a task's type: one per task type, in static
/// storage.
struct task_type_info {
    /// Returns the next task which is waiting for this task to complete
    /// execution, or nullptr.
    task* (*waiting_task)(task*) noexcept;
    const std::type_info* type;
};

namespace internal {

// Sits in front of the task subobject of every runnable_task, in the shape
// of the two words the compiler puts in front of a coroutine's promise. The
// first is a function the reactor calls with the header's address, as it
// calls a frame's resume function with the frame's address. The second,
// where the frame has its destroy function, holds the task's resume point.
//
// _run_fn is not noexcept because coroutine_handle<>::resume() is not either.
// With matching exception specifications the two calls in
// task::run_and_dispose() are the same call, and clang (23 and later)
// merges them into one indirect call.
struct task_header {
    void (*_run_fn)(task_header*);
    std::source_location _resume_point;
};

using task_run_fn = void (*)(task_header*);

// Maps each runnable task type's run function to its task_type_info, for
// diagnostics. Types register during static initialization; lookups do not
// allocate. Returns nullptr for a function that was never registered.
void register_task_type(task_run_fn run_fn, const task_type_info& info) noexcept;
const task_type_info* find_task_type(task_run_fn run_fn) noexcept;

}

/// Something the reactor runs: a runnable_task, or a coroutine_task (the
/// promise of a coroutine). Either way the function the reactor calls is
/// found 16 bytes in front of the task, so dispatch needs no virtual call.
class task {
protected:
    scheduling_group _sg;

private:
    bool _is_coroutine;
#ifdef SEASTAR_TASK_BACKTRACE
    shared_backtrace _bt;
#endif

    friend class runnable_task;
    friend class coroutine_task;

    task(scheduling_group sg, bool is_coroutine) noexcept : _sg(sg), _is_coroutine(is_coroutine) {}

    std::source_location& resume_point() noexcept;

    template <typename T>
    static task* waiting_task_of(task* t) noexcept {
        return static_cast<T*>(t)->T::waiting_task();
    }
    template <typename T>
    static void run_direct(internal::task_header* h) noexcept;
protected:
    // Task destruction is performed by run_and_dispose() via a concrete type,
    // so no need for a virtual destructor here. Derived classes that implement
    // run_and_dispose() should be declared final to avoid losing concrete type
    // information via inheritance.
    ~task() = default;

    scheduling_group set_scheduling_group(scheduling_group new_sg) noexcept{
        return std::exchange(_sg, new_sg);
    }

    template <typename T>
    static constexpr task_type_info type_info_of{&waiting_task_of<T>, &typeid(T)};
private:
    template <typename T>
    static inline const bool registered = (internal::register_task_type(&run_direct<T>, type_info_of<T>), true);
public:
    /// Runs the task, which usually destroys it.
    void run_and_dispose() noexcept;
    /// Returns the next task which is waiting for this task to complete execution, or nullptr.
    task* waiting_task() noexcept { return task_info().waiting_task(this); }
    const task_type_info& task_info() const noexcept;
    void update_resume_point(std::source_location sl) noexcept { resume_point() = sl; }
    std::source_location get_resume_point() const noexcept { return const_cast<task*>(this)->resume_point(); }
    scheduling_group group() const { return _sg; }
#ifdef SEASTAR_TASK_BACKTRACE
    void make_backtrace() noexcept;
    shared_backtrace get_backtrace() const { return _bt; }
#else
    void make_backtrace() noexcept {}
    shared_backtrace get_backtrace() const { return {}; }
#endif
};

/// Base of every task that is not a coroutine promise.
///
/// The final type T calls set_task_type<T>() from its constructor and
/// provides, without virtual:
///
///     [[gnu::always_inline]] void run_and_dispose() noexcept;
///     task* waiting_task() noexcept;
///
/// The reactor then calls T::run_and_dispose() through the header, with no
/// virtual call; always_inline puts the body straight into the function the
/// header points to.
class runnable_task : private internal::task_header, public task {
    friend class task;
    static void unregistered(internal::task_header*) noexcept {
        // A task type did not call set_task_type<>().
        std::abort();
    }
    static task* no_waiting_task(task*) noexcept { return nullptr; }
protected:
    static const task_type_info unregistered_info;

    explicit runnable_task(scheduling_group sg = current_scheduling_group()) noexcept
        : internal::task_header{&unregistered, {}}, task(sg, false) {}
    ~runnable_task() = default;

    template <typename T>
    void set_task_type() noexcept {
        static_assert(std::is_final_v<T>, "the reactor must reach the task's dynamic type");
        _run_fn = &task::run_direct<T>;
        (void)registered<T>;
    }
public:
    void update_resume_point(std::source_location sl) noexcept { _resume_point = sl; }
    std::source_location get_resume_point() const noexcept { return _resume_point; }
};

inline const task_type_info runnable_task::unregistered_info{&runnable_task::no_waiting_task, &typeid(runnable_task)};

/// Base of every coroutine promise that the reactor resumes. The coroutine
/// frame's resume and destroy pointers sit in front of it, where a
/// runnable_task has its header.
class coroutine_task : public task {
    friend class task;
    std::source_location _resume_point;
    const task_type_info* _info;
protected:
    // Call as coroutine_task(*this) from the constructor of Promise, the
    // coroutine's promise type.
    template <typename Promise>
    explicit coroutine_task(Promise& promise) noexcept
            : task(current_scheduling_group(), true), _info(&type_info_of<Promise>) {
        // A promise aligned to at most 16 bytes starts 16 bytes into its
        // frame, after the resume and destroy pointers, with this task at its
        // start. task::run_and_dispose() relies on it.
        static_assert(alignof(Promise) <= 16, "the promise must start 16 bytes into the coroutine frame");
        SEASTAR_ASSERT(std::coroutine_handle<Promise>::from_promise(promise).address()
                == reinterpret_cast<char*>(static_cast<task*>(this)) - 16);
    }
    ~coroutine_task() = default;
public:
    void update_resume_point(std::source_location sl) noexcept { _resume_point = sl; }
    std::source_location get_resume_point() const noexcept { return _resume_point; }
};

inline void task::run_and_dispose() noexcept {
    // Both arms call the function stored 16 bytes in front of this task with
    // that address: a coroutine frame's resume function, or a runnable_task's
    // header. They are the same call, so clang drops the test and emits one
    // indirect call.
    if (_is_coroutine) {
        std::coroutine_handle<>::from_address(reinterpret_cast<char*>(this) - 16).resume();
    } else {
        internal::task_header* h = static_cast<runnable_task*>(this);
        h->_run_fn(h);
    }
}

inline std::source_location& task::resume_point() noexcept {
    if (_is_coroutine) {
        return static_cast<coroutine_task*>(this)->_resume_point;
    }
    return static_cast<internal::task_header*>(static_cast<runnable_task*>(this))->_resume_point;
}

inline const task_type_info& task::task_info() const noexcept {
    if (_is_coroutine) {
        return *static_cast<const coroutine_task*>(this)->_info;
    }
    auto run_fn = static_cast<const internal::task_header*>(static_cast<const runnable_task*>(this))->_run_fn;
    auto info = internal::find_task_type(run_fn);
    return info ? *info : runnable_task::unregistered_info;
}

template <typename T>
void task::run_direct(internal::task_header* h) noexcept {
    static_cast<T*>(static_cast<runnable_task*>(h))->T::run_and_dispose();
}

void schedule(task* t) noexcept;
void schedule_checked(task* t) noexcept;
void schedule_urgent(task* t) noexcept;

}
