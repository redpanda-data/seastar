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
 * Copyright 2025 Redpanda Data, Inc.
 */
#pragma once

#include <seastar/core/chunked_vector.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/preempt.hh>
#include <seastar/util/assert.hh>
#include <seastar/util/later.hh>

#include <algorithm>

// Async helpers for chunked_vector.
// Not in the main header to avoid pulling in all of seastar if you just need
// chunked_vector.

namespace seastar {

/**
 * A futurized version of std::fill optimized for fragmented vector. It is
 * futurized to allow for large vectors to be filled without incurring reactor
 * stalls. It is optimized by circumventing the indexing indirection incurred by
 * using the fragmented vector interface directly.
 */
template<typename T>
future<> chunked_vector_fill_async(chunked_vector<T>& vec, const T& value) {
    auto remaining = vec._size;
    for (auto& frag : vec._frags) {
        const auto n = std::min(frag.size(), remaining);
        if (n == 0) {
            break;
        }
        std::fill_n(frag.begin(), n, value);
        remaining -= n;
        if (need_preempt()) {
            co_await yield();
        }
    }
    SEASTAR_ASSERT(
      remaining == 0
      && "chunked_vector_fill_async: fragmented vector inconsistency");
}

/**
 * A futurized version of chunked_vector::clear that allows clearing a large
 * vector without incurring a reactor stall.
 */
template<typename T>
future<> chunked_vector_clear_async(chunked_vector<T>& vec) {
    while (!vec._frags.empty()) {
        vec._frags.pop_back();
        if (need_preempt()) {
            co_await yield();
        }
    }
    vec.clear();
}

} // namespace seastar
