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
 * Copyright 2024 Redpanda Data
 */

#include "loopback_socket.hh"

#include <seastar/core/metrics.hh>
#include <seastar/core/prometheus.hh>
#include <seastar/http/common.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/testing/thread_test_case.hh>

#include <boost/test/tools/old/interface.hpp>

using namespace seastar;
using namespace httpd;

namespace {

struct test_metrics {
    metrics::metric_groups _metrics;

    void setup_metrics() {
        auto somelabel = metrics::label("somekey");

        _metrics.add_group("aaaa", {
            metrics::make_gauge("escaped_label_value_test", [] { return 10; }, metrics::description{"test that special characters are escaped"}, {somelabel(R"(special"\nvalue)")}),
            metrics::make_counter("counter_test", [] () -> int64_t { return 1234567654321; }, metrics::description{"test with an long counter value"}),
        });
    }
};

future<> test_prometheus_metrics_body() {
    test_metrics metrics;
    metrics.setup_metrics();

    co_await seastar::async([] {
        loopback_connection_factory lcf(1);
        http_server server("test");
        loopback_socket_impl lsi(lcf);
        httpd::http_server_tester::listeners(server).emplace_back(lcf.get_server_socket());

        prometheus::config ctx;
        add_prometheus_routes(server, ctx).get();

        future<> client = seastar::async([&lsi] {
            connected_socket c_socket = lsi.connect(socket_address(ipv4_addr()), socket_address(ipv4_addr())).get();
            input_stream<char> input(c_socket.input());
            output_stream<char> output(c_socket.output());

            output.write(sstring("GET /metrics HTTP/1.1\r\nHost: test\r\n\r\n")).get();
            output.flush().get();
            auto resp = input.read().get();
            auto resp_str = std::string(resp.get(), resp.size());
            BOOST_REQUIRE_NE(resp_str.find("200 OK"), std::string::npos);

            BOOST_REQUIRE_MESSAGE(resp_str.find(R"(seastar_aaaa_escaped_label_value_test{shard="0",somekey="special\"\\nvalue"} 10.000000)") != std::string::npos, "Response: " + resp_str);
            BOOST_REQUIRE_MESSAGE(resp_str.find(R"(seastar_aaaa_counter_test{shard="0"} 1234567654321)") != std::string::npos, "Response: " + resp_str);
            
            input.close().get();
            output.close().get();
        });

        server.do_accepts(0).get();

        client.get();
        server.stop().get();
    });
}

}

SEASTAR_TEST_CASE(test_prometheus_metrics) {
    return test_prometheus_metrics_body();
}
