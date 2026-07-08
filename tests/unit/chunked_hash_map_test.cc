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
 * Copyright 2024 Redpanda Data, Inc.
 */

#include <seastar/core/sstring.hh>
#define BOOST_TEST_MODULE chunked_hash_map

#include <seastar/core/chunked_hash_map.hh>

#include <boost/test/unit_test.hpp>

#include <array>
#include <list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using seastar::chunked_hash_map;
using seastar::chunked_hash_set;
using seastar::chunked_hash_map_from_range;
using seastar::chunked_hash_set_from_range;
using seastar::chunked_table_from_range;

struct foo_with_std_hash {
    int a;
    int b;
    auto operator<=>(const foo_with_std_hash&) const = default;
};

namespace std {

template<>
struct hash<foo_with_std_hash> {
    size_t operator()(const foo_with_std_hash& x) const {
        return std::hash<int>()(x.a + x.b);
    }
};

} // namespace std

struct foo_with_absl_hash {
    int a;
    int b;

    auto operator<=>(const foo_with_absl_hash&) const = default;

    template<typename H>
    friend H AbslHashValue(H h, const foo_with_absl_hash& x) {
        return H::combine(std::move(h), x.a, x.b);
    }
};

BOOST_AUTO_TEST_CASE(basic_compile_std_hash) {
    chunked_hash_map<foo_with_std_hash, int> map;
    map[{1, 2}] = 2;
    BOOST_REQUIRE_EQUAL(map.size(), 1u);
}

BOOST_AUTO_TEST_CASE(basic_compile_absl_hash) {
    static_assert(seastar::internal::has_absl_hash<foo_with_absl_hash>);
    chunked_hash_map<foo_with_absl_hash, int> map;
    map[{1, 2}] = 2;
    BOOST_REQUIRE_EQUAL(map.size(), 1u);
}

BOOST_AUTO_TEST_CASE(test_move_assignment) {
    chunked_hash_map<foo_with_absl_hash, int> map;
    chunked_hash_map<foo_with_absl_hash, int> other_map;
    other_map = std::move(map);
}

BOOST_AUTO_TEST_CASE(map_from_range_vector) {
    std::vector<std::pair<int, int>> input{{1, 10}, {2, 20}, {3, 30}};
    auto map = chunked_hash_map_from_range(input);
    chunked_hash_map<int, int> expected{{1, 10}, {2, 20}, {3, 30}};
    BOOST_REQUIRE(map == expected);
}

BOOST_AUTO_TEST_CASE(map_from_range_list) {
    std::list<std::pair<std::string, int>> input{
      {"one", 1}, {"two", 2}, {"three", 3}};
    auto map = chunked_hash_map_from_range(input);
    chunked_hash_map<std::string, int> expected{
      {"one", 1}, {"two", 2}, {"three", 3}};
    BOOST_REQUIRE(map == expected);
}

BOOST_AUTO_TEST_CASE(map_from_range_list_hetero) {
    using hetero_map_t = chunked_hash_map<
      std::string,
      int,
      ankerl::unordered_dense::hash<std::string_view>,
      std::equal_to<std::string_view>>;
    std::list<std::pair<seastar::sstring, int>> input{
      {"one", 1}, {"two", 2}, {"three", 3}};
    auto map = chunked_table_from_range<hetero_map_t>(input);
    hetero_map_t expected{
      {"one", 1}, {"two", 2}, {"three", 3}};
    BOOST_REQUIRE(map == expected);
}

BOOST_AUTO_TEST_CASE(map_from_range_array) {
    std::array<std::pair<const int, std::string>, 2> input{{{1, "one"}, {2, "two"}}};
    auto map = chunked_hash_map_from_range(input);
    chunked_hash_map<int, std::string> expected{{1, "one"}, {2, "two"}};
    BOOST_REQUIRE(map == expected);
}

BOOST_AUTO_TEST_CASE(set_from_range_vector) {
    std::vector<std::string> input{"foo", "bar", "baz"};
    auto set = chunked_hash_set_from_range(input);
    chunked_hash_set<std::string> expected{"foo", "bar", "baz"};
    BOOST_REQUIRE(set == expected);
}

BOOST_AUTO_TEST_CASE(set_from_range_vector_hetero) {
    using hetero_set_t = chunked_hash_set<
      std::string,
      ankerl::unordered_dense::hash<std::string_view>,
      std::equal_to<std::string_view>>;
    std::vector<seastar::sstring> input{"foo", "bar", "baz"};
    auto set = chunked_table_from_range<hetero_set_t>(input);
    hetero_set_t expected{"foo", "bar", "baz"};
    BOOST_REQUIRE(set == expected);
}
