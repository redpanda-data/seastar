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
