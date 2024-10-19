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
 * Copyright (C) 2019 ScyllaDB Ltd.
 */

#pragma once

#include "syscall_work_queue.hh"

namespace seastar {

class reactor;

// Reasons for why a function had to be submitted to the thread_pool 
enum class submit_reason : size_t {
    // Used for aio operations what would block in `io_submit`.
    aio_fallback,
    // Used for file operations that don't have non-blocking alternatives.
    file_operation,
    // Used for process operations that don't have non-blocking alternatives.
    process_operation,
    // Used by default when a caller doesn't specify a submission reason.
    unknown,
};

class submit_metrics {
    uint64_t _counters[static_cast<size_t>(submit_reason::unknown) + 1]{};

public:
    void record_reason(submit_reason reason) {
        reason = std::min(reason, submit_reason::unknown);
        ++_counters[static_cast<size_t>(reason)];
    }

    uint64_t count_for(submit_reason reason) const {
        reason = std::min(reason, submit_reason::unknown);
        return _counters[static_cast<size_t>(reason)];
    }
};

class thread_pool {
    reactor& _reactor;
    submit_metrics metrics;
#ifndef HAVE_OSV
    syscall_work_queue inter_thread_wq;
    posix_thread _worker_thread;
    std::atomic<bool> _stopped = { false };
    std::atomic<bool> _main_thread_idle = { false };
public:
    explicit thread_pool(reactor& r, sstring thread_name);
    ~thread_pool();
    template <typename T, typename Func>
    future<T> submit(Func func, submit_reason reason = submit_reason::unknown) noexcept {
        metrics.record_reason(reason);
        return inter_thread_wq.submit<T>(std::move(func));
    }
    uint64_t count(submit_reason r) const { return metrics.count_for(r); }

    unsigned complete() { return inter_thread_wq.complete(); }
    // Before we enter interrupt mode, we must make sure that the syscall thread will properly
    // generate signals to wake us up. This means we need to make sure that all modifications to
    // the pending and completed fields in the inter_thread_wq are visible to all threads.
    //
    // Simple release-acquire won't do because we also need to serialize all writes that happens
    // before the syscall thread loads this value, so we'll need full seq_cst.
    void enter_interrupt_mode() { _main_thread_idle.store(true, std::memory_order_seq_cst); }
    // When we exit interrupt mode, however, we can safely used relaxed order. If any reordering
    // takes place, we'll get an extra signal and complete will be called one extra time, which is
    // harmless.
    void exit_interrupt_mode() { _main_thread_idle.store(false, std::memory_order_relaxed); }

#else
public:
    template <typename T, typename Func>
    future<T> submit(Func func, submit_reason reason = submit_reason::unknown) { std::cerr << "thread_pool not yet implemented on osv\n"; abort(); }
#endif
private:
    void work(sstring thread_name);
};


}
