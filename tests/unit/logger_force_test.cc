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

SEASTAR_THREAD_TEST_CASE(force_bypasses_level_gate_convenience_methods) {
    std::ostringstream captured;
    seastar::logger::set_ostream(captured);
    seastar::logger::set_ostream_enabled(true);

    test_log.set_level(seastar::log_level::warn);

    test_log.info(seastar::logger::force, "info_forced");
    test_log.debug(seastar::logger::force, "debug_forced");
    test_log.trace(seastar::logger::force, "trace_forced");
    test_log.warn(seastar::logger::force, "warn_forced");
    test_log.error(seastar::logger::force, "error_forced");

    const auto out = captured.str();
    BOOST_REQUIRE(out.find("info_forced")  != std::string::npos);
    BOOST_REQUIRE(out.find("debug_forced") != std::string::npos);
    BOOST_REQUIRE(out.find("trace_forced") != std::string::npos);
    BOOST_REQUIRE(out.find("warn_forced")  != std::string::npos);
    BOOST_REQUIRE(out.find("error_forced") != std::string::npos);

    // Without force, info/debug/trace dropped under warn level.
    captured.str("");
    test_log.info("info_dropped");
    BOOST_REQUIRE(captured.str().find("info_dropped") == std::string::npos);
}
