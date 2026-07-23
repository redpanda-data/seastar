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
