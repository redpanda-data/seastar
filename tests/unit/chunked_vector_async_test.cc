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

#include <seastar/core/chunked_vector.hh>
#include <seastar/core/chunked_vector_async.hh>
#include <seastar/testing/thread_test_case.hh>

using seastar::chunked_vector;

SEASTAR_THREAD_TEST_CASE(chunked_vector_fill_async_test) {
    chunked_vector<int> v;
    chunked_vector_fill_async(v, 0).get();
    BOOST_REQUIRE(v.size() == 0);

    // fill with non-zero
    for (int i = 1; i <= 10; ++i) {
        v.push_back(i);
    }
    BOOST_REQUIRE(v.size() == 10);
    for (const auto& e : v) {
        BOOST_REQUIRE(e > 0);
    }

    // fill with zero
    chunked_vector_fill_async(v, 0).get();
    BOOST_REQUIRE(v.size() == 10);
    for (const auto& e : v) {
        BOOST_REQUIRE(e == 0);
    }
}

SEASTAR_THREAD_TEST_CASE(chunked_vector_clear_async_test) {
    chunked_vector<int> v;
    chunked_vector_clear_async(v).get();
    BOOST_REQUIRE(v.size() == 0);

    // one element
    v.push_back(0);
    BOOST_REQUIRE(v.size() == 1);
    chunked_vector_clear_async(v).get();
    BOOST_REQUIRE(v.size() == 0);

    // many fragments
    for (size_t i = 0; i < 5; ++i) {
        for (size_t j = 0; j < v.elements_per_fragment(); ++j) {
            v.push_back(j);
        }
    }
    BOOST_REQUIRE(v.size() == (5 * v.elements_per_fragment()));

    chunked_vector_clear_async(v).get();
    BOOST_REQUIRE(v.size() == 0);
}
