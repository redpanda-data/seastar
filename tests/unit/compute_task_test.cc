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
