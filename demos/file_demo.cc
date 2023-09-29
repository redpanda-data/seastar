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

#include "seastar/core/when_all.hh"
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

using namespace seastar;

future<> demo_with_file(size_t seconds, size_t aligned_size, size_t blocks, sstring file1, sstring file2) {
    fmt::print("Demonstrating with_file():\n");
    auto wbuf = temporary_buffer<char>::aligned(aligned_size, blocks * aligned_size);
    std::fill(wbuf.get_write(), wbuf.get_write() + aligned_size, 'a');

    std::vector<file> files;

    for (size_t i = 0; i < blocks; ++i) {
        files.push_back(co_await open_file_dma(file1 + std::to_string(i), open_flags::rw | open_flags::create));
    }

    file slow_file;
    if (!file2.empty()) {
        slow_file = co_await open_file_dma(file2, open_flags::rw | open_flags::create);
    }

    std::vector<future<>> futs;
    futs.reserve(blocks);

    future<size_t> slow_fut = make_ready_future<size_t>(0);

    for (size_t i = 0; i < seconds; ++i) {
        size_t count = 0;
        auto start = std::chrono::steady_clock::now();
        auto end = start + std::chrono::seconds(1);

        while (start < end) {
            if (!file2.empty() && slow_fut.available()) {
                slow_fut = slow_file.dma_write(0, wbuf.get(), aligned_size);
            }

            for (size_t i = 0; i < blocks; ++i) {
                futs.push_back(files[0].dma_write(i * aligned_size, wbuf.get(), aligned_size)
                    .then([&files, i] (size_t) { return files[i].flush(); }));
            }
            co_await when_all_succeed(futs.begin(), futs.end());
            futs.clear();

            start = std::chrono::steady_clock::now();
            count += blocks;
        }

        fmt::print("{} iops {} MB/s\n", count, count * aligned_size / 1024 / 1024);

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
        ("file2", bpo::value<sstring>()->default_value("file2"), "")
        ;
    return app.run(ac, av, [&app] () -> future<> {
        auto&& config = app.configuration();
        auto chunk_size = config["size"].as<size_t>();
        auto seconds = config["seconds"].as<size_t>();
        auto blocks = config["blocks"].as<size_t>();
        auto file1 = config["file1"].as<sstring>();
        auto file2 = config["file2"].as<sstring>();
        co_return co_await demo_with_file(seconds, chunk_size, blocks, file1, file2);
    });
}
