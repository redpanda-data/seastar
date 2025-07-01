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

#include "seastar/core/abort_source.hh"
#include "seastar/core/future.hh"
#include <seastar/testing/perf_tests.hh>

struct perf_abort_source {};

PERF_TEST_F(perf_abort_source, abort_default_exception)
{
    constexpr size_t source_count = 10000;

    std::vector<abort_source> as_vec;

    for (size_t i = 0; i < source_count; ++i) {
        as_vec.push_back(abort_source());
    }

    perf_tests::start_measuring_time();
    for (auto& as : as_vec) {
        as.request_abort();
    }
    perf_tests::stop_measuring_time();

    return as_ready_future(source_count);
}
