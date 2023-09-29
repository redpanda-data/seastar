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
 * Copyright 2020 ScyllaDB
 */


// Demonstration of seastar::with_file

#include "seastar/core/future.hh"
#include "seastar/core/reactor.hh"
#include "seastar/core/when_all.hh"
#include <chrono>
#include <cstring>
#include <limits>
#include <random>

#include <seastar/core/app-template.hh>

#include <seastar/core/aligned_buffer.hh>
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/io_intent.hh>
#include <seastar/util/log.hh>
#include <seastar/util/tmp_file.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/io_priority_class.hh>
#include <seastar/core/io_queue.hh>

using namespace seastar;

future<> demo_with_file(size_t seconds, size_t aligned_size, size_t blocks, sstring file1, io_priority_class& prio_class) {
    auto wbuf = temporary_buffer<char>::aligned(aligned_size, blocks * aligned_size);
    std::fill(wbuf.get_write(), wbuf.get_write() + aligned_size, 'a');

    std::vector<file> files;

    for (size_t i = 0; i < blocks; ++i) {
        files.push_back(co_await open_file_dma(file1 + std::to_string(i), open_flags::rw | open_flags::create));
    }

    std::vector<future<>> futs;
    futs.reserve(blocks);

    for (size_t i = 0; i < seconds; ++i) {
        auto polls = engine()._polls;
        auto sleeps = engine()._sleeps;
        auto start_total_sleep = engine()._total_sleep;
        size_t count = 0;
        auto start = std::chrono::steady_clock::now();
        auto end = start + std::chrono::seconds(1);

        while (start < end) {
            for (size_t i = 0; i < blocks; ++i) {
                futs.push_back(files[i].dma_write(0, wbuf.get(), aligned_size, prio_class)
                    .then([&files, i] (size_t) { return files[i].flush(); }));
            }
            co_await when_all_succeed(futs.begin(), futs.end());
            futs.clear();

            start = std::chrono::steady_clock::now();
            count += blocks;
        }

        auto polls_per_second = engine()._polls - polls;
        auto sleeps_per_second = engine()._sleeps - sleeps;
        auto average_sleep_time = sleeps_per_second ? (engine()._total_sleep - start_total_sleep) / sleeps_per_second : std::chrono::microseconds(0);
        fmt::print("{}: {} iops {} MB/s {} polls {} sleeps {} average-sleep-us\n", file1, count,
                   count * aligned_size / 1024 / 1024,
                   polls_per_second,
                   sleeps_per_second,
                   average_sleep_time / std::chrono::microseconds(1));
    }
}

namespace bpo = boost::program_options;

int main(int ac, char** av) {
    app_template app;
    app.add_options()
        ("seconds", bpo::value<size_t>()->default_value(10), "")
        ("blocks", bpo::value<size_t>()->default_value(64), "")
        ("size", bpo::value<size_t>()->default_value(4096), "")
        ("file1", bpo::value<sstring>()->default_value("file1"), "")
        ("file2", bpo::value<sstring>(), "")
        ("slow-prio", bpo::value<bool>()->default_value(false), "")
        ;
    return app.run(ac, av, [&app] () -> future<> {
        auto&& config = app.configuration();
        auto chunk_size = config["size"].as<size_t>();
        auto seconds = config["seconds"].as<size_t>();
        auto blocks = config["blocks"].as<size_t>();
        auto file1 = config["file1"].as<sstring>();
        auto file2 = config.contains("file2") ? config["file2"].as<sstring>() : sstring();
        bool use_prio = config["slow-prio"].as<bool>();

        auto fast_prio_class = io_priority_class::register_one("fast", 1000);
        auto slow_prio_class = io_priority_class::register_one("slow", 1);

        auto fast_fut = demo_with_file(seconds, chunk_size, blocks, file1, fast_prio_class);
        auto slow_fut = make_ready_future();
        
        if (!file2.empty()) {
            slow_fut = demo_with_file(seconds, chunk_size, blocks, file2, use_prio ? slow_prio_class : fast_prio_class);
        } 

        co_await std::move(fast_fut);
        co_await std::move(slow_fut);
        co_return;
    });
}
