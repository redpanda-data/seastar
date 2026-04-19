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
 * Copyright 2026 Redpanda Data, Inc.
 */

#pragma once

#include <seastar/core/future.hh>
#include <seastar/core/task.hh>
#include <seastar/util/defer.hh>

namespace seastar {

/// \addtogroup future-util
/// @{

/// \brief Run a callable with \c ctx installed as the current task context.
///
/// TLS is set to \c ctx for the duration of \c func's synchronous
/// execution, so tasks created inline (coroutine promises, \c .then()
/// continuations, etc.) inherit \c ctx at construction and carry it
/// through their own suspensions via their own \c task._context. The
/// caller's \c task._context is never modified, so this is safe
/// regardless of what task is running when invoked.
///
/// \param ctx context to install; empty clears the context for the scope.
/// \param func callable returning a future; its async work inherits \c ctx.
/// \param args forwarded to \c func.
template <typename Func, typename... Args>
inline
auto
with_context([[maybe_unused]] const lw_shared_ptr<task_context>& ctx,
             Func&& func, Args&&... args) noexcept {
#ifdef SEASTAR_TASK_CONTEXT
    auto* prev = current_task_context();
    set_current_task_context(ctx.get());
    auto restore = defer([prev] () noexcept {
        set_current_task_context(prev);
    });
#endif
    return futurize_invoke(std::forward<Func>(func), std::forward<Args>(args)...);
}

/// @}

} // namespace seastar
