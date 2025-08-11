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
 * Copyright (C) 2016 ScyllaDB
 */

#pragma once

#ifndef SEASTAR_MODULE
#include <seastar/http/httpd.hh>
#include <seastar/core/metrics.hh>
#include <seastar/util/std-compat.hh>
#include <seastar/util/modules.hh>
#include <optional>
#endif

namespace seastar {

namespace prometheus {

SEASTAR_MODULE_EXPORT_BEGIN

/*!
 * Holds prometheus related configuration
 */
struct config {
    sstring metric_help; //!< Default help message for the returned metrics
    sstring hostname; //!< hostname is deprecated, use label instead
    std::optional<metrics::label_instance> label; //!< A label that will be added to all metrics, we advice not to use it and set it on the prometheus server
    sstring prefix = "seastar"; //!< a prefix that will be added to metric names
    bool allow_protobuf = false; // protobuf support is experimental and off by default
    int handle = metrics::default_handle(); //!< Handle that specifies which metric implementation to query
    sstring route = "/metrics"; //!< Name of the route on which to expose the metrics
};

future<> start(httpd::http_server_control& http_server, config ctx);

/// \defgroup add_prometheus_routes adds a specified endpoint (defaults to /metrics) that returns prometheus metrics
///    in txt format format and in protobuf according to the prometheus spec

/// @{
future<> add_prometheus_routes(distributed<httpd::http_server>& server, config ctx);
future<> add_prometheus_routes(httpd::http_server& server, config ctx);
/// @}
SEASTAR_MODULE_EXPORT_END
}
}
