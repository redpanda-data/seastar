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
 * Copyright (C) 2023 ScyllaDB Ltd.
 */

#include <atomic>
#include <chrono>
#include <cstddef>

#include <seastar/core/internal/cpu_profiler.hh>
#include <seastar/core/internal/stall_detector.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/scheduling.hh>
#include <seastar/core/thread_cputime_clock.hh>
#include <seastar/core/with_scheduling_group.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/testing/thread_test_case.hh>
#include <seastar/util/defer.hh>
#include <seastar/util/later.hh>

#include "stall_detector_test_utilities.hh"

#include <sys/mman.h>

#include <boost/test/tools/old/interface.hpp>

namespace {

struct temporary_profiler_settings {
    std::chrono::nanoseconds prev_ns;
    bool prev_enabled;

    temporary_profiler_settings(bool enable, std::chrono::nanoseconds ns) {
        prev_ns = engine().get_cpu_profiler_period();
        prev_enabled = engine().get_cpu_profiler_enabled();

        engine().set_cpu_profiler_period(ns);
        engine().set_cpu_profiler_enabled(enable);
    }

    ~temporary_profiler_settings() {
        engine().set_cpu_profiler_period(prev_ns);
        engine().set_cpu_profiler_enabled(prev_enabled);
    }
};

// If we set a timer to fire in N ms we can expect it to fire between N and (N + E) ms from
// when it was set. Where E is some fixed error that arises from how granular a given timer
// is. Therefore over a given period of time, M, if the timer is continously reset every
// time it fires we can expect the timer to fire between M/N and M/(N+E) times.
//
// The function below takes this error into account and allows the actual samples taken
// to be slightly less than the expect number of samples if there was no error.
bool close_to_expected(size_t actual_size, size_t expected_size, double allowed_dev = 0.15) {
    auto lower_bound = (1 - allowed_dev) * expected_size;
    auto upper_bound = (1 + allowed_dev) * expected_size;

    BOOST_TEST_INFO("actual_size: " << actual_size << ", lower_bound " << lower_bound << ", upper_bound " << upper_bound);

    return actual_size <= upper_bound && actual_size >= lower_bound;
}

/*
 * Get the current profile results and dropped count. If sg_in_main is true, also validates that
 * the sg associated with the profile is always main, as we expect unless some SG have been
 * created explicitly.
 */
std::pair<std::vector<cpu_profiler_trace>, size_t> get_profile_and_dropped(bool sg_is_main = true) {
    std::vector<cpu_profiler_trace> results;
    auto dropped = engine().profiler_results(results);

    for (auto& result: results) {
        BOOST_CHECK(result.sg == default_scheduling_group());
    }

    return {results, dropped};
}


// get profile and validate results
std::vector<cpu_profiler_trace> get_profile() {
    return get_profile_and_dropped().first;
}

}



SEASTAR_THREAD_TEST_CASE(config_case) {
    // Ensure that repeatedly configuring the profiler results
    // in expected behavior.
    {
        temporary_profiler_settings cp_0{true, 10ms};
        temporary_profiler_settings cp_1{true, 20ms};
        temporary_profiler_settings cp_2{false, 30ms};
        temporary_profiler_settings cp_3{true, 10ms};
        temporary_profiler_settings cp_4{true, 100ms};

        spin_some_cooperatively(120*10ms);

        auto results = get_profile();
        BOOST_REQUIRE(close_to_expected(results.size(), 12));
    }

    spin_some_cooperatively(128*10ms);
    auto results = get_profile();
    BOOST_REQUIRE_EQUAL(results.size(), 0);
}

SEASTAR_THREAD_TEST_CASE(simple_case) {
    temporary_profiler_settings cp{true, 100ms};

    spin_some_cooperatively(120*10ms);

    auto [results, dropped_samples] = get_profile_and_dropped();
    BOOST_REQUIRE(close_to_expected(results.size(), 12));
    BOOST_REQUIRE_EQUAL(dropped_samples, 0);
}

SEASTAR_THREAD_TEST_CASE(overwrite_case) {
    // Ensure that older samples are being overridden in
    // the cases where we can't collect results fast enough.
    temporary_profiler_settings cp{true, 10ms};

    spin_some_cooperatively(256*10ms);

    auto [results, dropped_samples] = get_profile_and_dropped();
    // 128 is the maximum number of samples the profiler can
    // retain.
    BOOST_REQUIRE_EQUAL(results.size(), 128);
    BOOST_REQUIRE(dropped_samples > 0);
}

SEASTAR_THREAD_TEST_CASE(mixed_case) {
    // Ensure that the profiler and cpu_stall_detector don't effect
    // the functioning of the other.
    std::atomic<unsigned> reports{};
    temporary_stall_detector_settings tsds(10ms, [&] { ++reports; });
    temporary_profiler_settings cp{true, 100ms};

    unsigned nr = 10;
    for (unsigned i = 0; i < nr; ++i) {
        spin_some_cooperatively(100ms);
        spin(20ms);
    }

    BOOST_REQUIRE_EQUAL(reports, 5);
    auto results = get_profile();
    BOOST_REQUIRE(close_to_expected(results.size(), 12));
}

SEASTAR_THREAD_TEST_CASE(spin_in_kernel) {
    // Check that we are correctly sampling the kernel stack.
    temporary_profiler_settings cp{true, 10ms};

    spin_some_cooperatively(100ms, [] { mmap_populate(128 * 1024); });

    auto results = get_profile();
    int count = 0;
    for(auto& result : results) {
        if(result.kernel_backtrace.size() > 0){
            count++;
        }
    }

    // There is no way to ensure every result has a kernel callstack.
    // And if we're using the posix timer then no callstacks will be
    // sampled. So we can't have an assertion here.
    testlog.info("sampled {} kernel callstacks", count);

    BOOST_REQUIRE(results.size() > 0);
}

SEASTAR_THREAD_TEST_CASE(signal_mutex_basic) {
    // A very basic test that ensures the signal_mutex
    // can't be re-locked after it's already been acquired.
    internal::signal_mutex mutex;

    {
        auto guard_opt_1 = mutex.try_lock();
        BOOST_REQUIRE(guard_opt_1.has_value());

        auto guard_opt_2 = mutex.try_lock();
        BOOST_REQUIRE(!guard_opt_2.has_value());
    }

    auto guard_opt_3 = mutex.try_lock();
    BOOST_REQUIRE(guard_opt_3.has_value());
}

namespace {
void random_exception_catcher(int p, int a);

[[gnu::noinline]] void
random_exception_thrower(int a) {
  static thread_local std::random_device rd;
  static thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<> d(1, 100);

  a -= 1;

  if (a <= 0) {
    throw std::invalid_argument("noop");
  }

  random_exception_catcher(d(gen), a);
}

[[gnu::noinline]] void random_exception_catcher(int p, int a) {
  static thread_local std::random_device rd;
  static thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<> d(1, 100);

  try {
    random_exception_thrower(a);
  } catch (...) {
    int r = d(gen);
    if (r > p) {
      throw;
    }
  }
}

} // namespace

SEASTAR_THREAD_TEST_CASE(exception_handler_case) {

  // disable for now, CORE-9144
  return;
  // Ensure that exception unwinding doesn't cause any issues
  // while profiling.
  temporary_profiler_settings cp{true, 1us};

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> d(1, 100);
  for (int a = 0; a < 10000; a++) {
    random_exception_catcher(100, d(gen));
  }

  auto [results, dropped_samples] = get_profile_and_dropped();
  BOOST_REQUIRE_EQUAL(results.size(), 128);
  BOOST_REQUIRE(dropped_samples > 0);
}

SEASTAR_THREAD_TEST_CASE(manually_disable) {
  // Ensure that manually disabling the profile backtracing works
  seastar::internal::scoped_disable_profile_temporarily profiling_disabled;
  temporary_profiler_settings cp{true, 10us};

  spin_some_cooperatively(100ms);

  auto [_, dropped_samples] = get_profile_and_dropped();
  BOOST_REQUIRE(dropped_samples > 0);
}

SEASTAR_THREAD_TEST_CASE(config_thrashing) {

  // disable for now, CORE-9144
  return;
  // Ensure that fast config changes leave the profiler in a valid
  // state.
  temporary_profiler_settings cp{true, 1us};

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> d(1, 100);

  for (int a = 0; a < 100; a++) {
    int r = d(gen);
    temporary_profiler_settings cp_0{r % 2 == 0, std::chrono::microseconds(r)};
    spin_some_cooperatively(1us);
  }

  auto results = get_profile();
  BOOST_REQUIRE(results.size() > 0);
}

SEASTAR_THREAD_TEST_CASE(scheduling_group_test) {

    [[maybe_unused]] auto sg_a = create_scheduling_group("sg_a", 200).get();
    [[maybe_unused]] auto sg_b = create_scheduling_group("sg_b", 200).get();

    auto destoy_groups = defer([&]() noexcept {
        destroy_scheduling_group(sg_b).get();
        destroy_scheduling_group(sg_a).get();
    });

    temporary_profiler_settings cp{true, 100ms};

    auto fut_a = with_scheduling_group(sg_a, [] {
        return spin_some_cooperatively_coro(2100ms);
    });

    with_scheduling_group(sg_b, [] {
        return spin_some_cooperatively_coro(2100ms);
    }).get();

    std::move(fut_a).get();

    std::vector<cpu_profiler_trace> results;
    auto dropped_samples = engine().profiler_results(results);

    size_t count_a = 0, count_b = 0, count_main = 0;
    for (auto& r : results) {
        if (r.sg == sg_a) {
            ++count_a;
        } else if (r.sg == sg_b) {
            ++count_b;
        } else if (r.sg == default_scheduling_group()) {
            // this happens when the profiler triggers during non-task
            // work, such as in the reactor pollers
            ++count_main;
        } else {
            BOOST_TEST_FAIL("unexpected SG: " << r.sg.name());
        }
    }

    // We expect a and b to be a 1:1 ratio, though we accept large
    // variance since this is random sampling of two "randomly" scheduled
    // groups so we don't really have the same guarantees we do in the
    // single group case where we expect sort of +/- 1 due to the way we
    // calculate the sampling intervals.
    // Nominally the split is 10/10/0 for a/b/main, but we just look for
    // at least 1 event in each to avoid flakiness.
    BOOST_CHECK_GT(count_a + count_b, 10);
    BOOST_CHECK_GT(count_a, 0);
    BOOST_CHECK_GT(count_b, 0);
    BOOST_CHECK_LT(count_main, 3);
    BOOST_CHECK_LT(dropped_samples, 5);
}
