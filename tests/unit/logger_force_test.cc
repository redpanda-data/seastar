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

#include <seastar/testing/thread_test_case.hh>
#include <seastar/util/log.hh>

#include <sstream>

namespace {
seastar::logger test_log("test");
}

SEASTAR_THREAD_TEST_CASE(force_bypasses_level_gate_log_overload) {
    std::ostringstream captured;
    seastar::logger::set_ostream(captured);
    seastar::logger::set_ostream_enabled(true);

    test_log.set_level(seastar::log_level::warn);

    // Without force: dropped.
    test_log.log(seastar::log_level::info, "dropped_line");
    BOOST_REQUIRE(captured.str().find("dropped_line") == std::string::npos);

    // With force: emitted.
    test_log.log(seastar::log_level::info, seastar::logger::force, "forced_line");
    BOOST_REQUIRE(captured.str().find("forced_line") != std::string::npos);
}
