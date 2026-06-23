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

#define BOOST_TEST_MODULE chunked_vector

#include <seastar/core/chunked_vector.hh>
#include <seastar/core/sstring.hh>

#include <boost/test/unit_test.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <numeric>
#include <random>
#include <ranges>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using seastar::chunked_vector;
using vec = chunked_vector<int>;

static_assert(std::random_access_iterator<vec::iterator>);
static_assert(std::random_access_iterator<vec::const_iterator>);
static_assert(std::ranges::random_access_range<vec>);
static_assert(std::ranges::random_access_range<const vec>);

namespace seastar {

class chunked_vector_validator {
public:
    // Perform an internal consistency check of the vector structure. Returns
    // an empty string on success, otherwise a description of the inconsistency.
    template<typename T>
    static std::string validate(const chunked_vector<T>& v) {
        if (v._size > v._capacity) {
            return "size greater than capacity";
        }
        if (v._size >= std::numeric_limits<size_t>::max() / 2) {
            return "size too big";
        }
        if (v._capacity >= std::numeric_limits<size_t>::max() / 2) {
            return "capacity too big";
        }
        size_t calc_size = 0, calc_cap = 0;

        for (size_t i = 0; i < v._frags.size(); ++i) {
            auto& f = v._frags[i];

            calc_size += f.size();
            calc_cap += f.capacity();

            if (i + 1 < v._frags.size()) {
                if (f.size() < v.elements_per_fragment()) {
                    return fmt::format(
                      "fragment {} is undersized ({} < {})",
                      i,
                      f.size(),
                      v.elements_per_fragment());
                }
            }
            if (f.capacity() > std::decay_t<decltype(v)>::max_frag_bytes()) {
                return fmt::format(
                  "fragment {} capacity over max_frag_bytes ({})", i, calc_cap);
            }
        }

        if (calc_size != v.size()) {
            return fmt::format(
              "calculated size is wrong ({} != {})", calc_size, v.size());
        }
        if (calc_cap != v._capacity) {
            return fmt::format(
              "calculated capacity is wrong ({} != {})", calc_cap, v._capacity);
        }
        return {};
    }
};

} // namespace seastar

using seastar::chunked_vector_validator;

namespace {

// Minimal replacement for redpanda's random_generators used by these tests.
std::mt19937& test_rng() {
    static std::mt19937 engine{std::random_device{}()};
    return engine;
}

// Returns a value in the inclusive range [0, max].
template<typename I = int>
I get_int(I max) {
    return std::uniform_int_distribution<I>(0, max)(test_rng());
}

// Returns a value in the inclusive range [min, max].
template<typename I>
I get_int(I min, I max) {
    return std::uniform_int_distribution<I>(min, max)(test_rng());
}

#define ASSERT_VALID(v)                                                        \
    do {                                                                       \
        auto err = chunked_vector_validator::validate(v);                      \
        BOOST_REQUIRE_MESSAGE(err.empty(), err);                               \
    } while (0)

/**
 * Proxy that applies a consistency check before deference
 */
template<typename T>
struct checker {
    using underlying = chunked_vector<T>;

    static checker<T> make(std::vector<T> in) {
        checker ret;
        for (auto& e : in) {
            ret->push_back(e);
        }
        return ret;
    }

    underlying* operator->() {
        auto err = chunked_vector_validator::validate(u);
        if (!err.empty()) {
            throw std::runtime_error(err);
        }
        return &u;
    }

    underlying& get() { return *operator->(); }

    auto operator<=>(const checker&) const = default;

    underlying u;
};

template<typename T>
void check_eq(chunked_vector<T>& impl, const std::vector<T>& shadow) {
    BOOST_REQUIRE_MESSAGE(
      std::equal(impl.begin(), impl.end(), shadow.begin(), shadow.end()),
      "iterators not equal");
    BOOST_REQUIRE_EQUAL(impl.empty(), shadow.empty());
    BOOST_REQUIRE_EQUAL(impl.size(), shadow.size());
    ASSERT_VALID(impl);
}

void push(chunked_vector<int>& impl, std::vector<int>& shadow, int count) {
    for (int i = 0; i < count; ++i) {
        shadow.push_back(i);
        impl.push_back(i);
        check_eq(impl, shadow);
    }
}

void pop(chunked_vector<int>& impl, std::vector<int>& shadow, int count) {
    for (int i = 0; i < count; ++i) {
        shadow.pop_back();
        impl.pop_back();
        check_eq(impl, shadow);
    }
}

BOOST_AUTO_TEST_CASE(PushPop) {
    std::vector<int> shadow;
    chunked_vector<int> impl;
    BOOST_REQUIRE(impl.empty());
    push(impl, shadow, 2500);
    pop(impl, shadow, 1234);
    push(impl, shadow, 123);
    pop(impl, shadow, 1389);
    BOOST_REQUIRE(std::ranges::equal(impl, shadow));
    BOOST_REQUIRE_EQUAL(impl.empty(), shadow.empty());
    BOOST_REQUIRE_EQUAL(impl.size(), shadow.size());
}

BOOST_AUTO_TEST_CASE(Iterator) {
    std::vector<int> shadow;
    chunked_vector<int> impl;

    push(impl, shadow, 2000);
    for (int i = 0; i < 6000; i++) {
        auto val = get_int<int64_t>(0, 4000);

        auto it = std::lower_bound(shadow.begin(), shadow.end(), val);
        auto it2 = std::lower_bound(impl.begin(), impl.end(), val);
        BOOST_REQUIRE_EQUAL(it == shadow.end(), it2 == impl.end());
        BOOST_REQUIRE_EQUAL(
          std::distance(shadow.begin(), it), std::distance(impl.begin(), it2));
        BOOST_REQUIRE_EQUAL(
          std::distance(it, shadow.end()), std::distance(it2, impl.end()));

        it = std::upper_bound(shadow.begin(), shadow.end(), val);
        it2 = std::upper_bound(impl.begin(), impl.end(), val);
        BOOST_REQUIRE_EQUAL(it == shadow.end(), it2 == impl.end());
        BOOST_REQUIRE_EQUAL(
          std::distance(shadow.begin(), it), std::distance(impl.begin(), it2));
        BOOST_REQUIRE_EQUAL(
          std::distance(it, shadow.end()), std::distance(it2, impl.end()));

        it = std::find(shadow.begin(), shadow.end(), val);
        it2 = std::find(impl.begin(), impl.end(), val);
        BOOST_REQUIRE_EQUAL(it == shadow.end(), it2 == impl.end());
        BOOST_REQUIRE_EQUAL(
          std::distance(shadow.begin(), it), std::distance(impl.begin(), it2));
        BOOST_REQUIRE_EQUAL(
          std::distance(it, shadow.end()), std::distance(it2, impl.end()));
    }
}

BOOST_AUTO_TEST_CASE(IteratorTypes) {
    using vtype = chunked_vector<int64_t>;
    using iter = vtype::iterator;
    using citer = vtype::const_iterator;
    using riter = vtype::reverse_iterator;
    using criter = vtype::const_reverse_iterator;
    auto v = vtype{};

    // const and non-const iterators should be different!
    static_assert(!std::is_same_v<iter, citer>);
    static_assert(std::is_same_v<decltype(v.begin()), iter>);
    static_assert(
      std::is_same_v<decltype(v.cbegin()), decltype(v)::const_iterator>);
    static_assert(std::is_same_v<
                  decltype(std::as_const(v).begin()),
                  decltype(v)::const_iterator>);

    // const and non-const reverse iterators should be different!
    static_assert(!std::is_same_v<riter, criter>);
    static_assert(std::is_same_v<decltype(v.rbegin()), riter>);
    static_assert(
      std::
        is_same_v<decltype(v.crbegin()), decltype(v)::const_reverse_iterator>);
    static_assert(std::is_same_v<
                  decltype(std::as_const(v).rbegin()),
                  decltype(v)::const_reverse_iterator>);
}

struct foo {
    int a;
    bool operator==(const foo&) const = default;
};

BOOST_AUTO_TEST_CASE(IteratorAccess) {
    using vtype = chunked_vector<foo>;
    auto vec = vtype{};
    vec.push_back(foo{2});

    BOOST_REQUIRE(*vec.begin() == foo{2});
    BOOST_REQUIRE_EQUAL((*vec.begin()).a, 2);
    BOOST_REQUIRE_EQUAL(vec.begin()->a, 2);
}

BOOST_AUTO_TEST_CASE(ReverseIteratorAccess) {
    using vtype = chunked_vector<foo>;
    auto vec = vtype{};
    vec.push_back(foo{2});
    vec.push_back(foo{3});

    BOOST_REQUIRE(*vec.rbegin() == foo{3});
    BOOST_REQUIRE_EQUAL((*vec.rbegin()).a, 3);
    BOOST_REQUIRE_EQUAL(vec.rbegin()->a, 3);
}

BOOST_AUTO_TEST_CASE(IteratorArithmetic) {
    auto v = checker<int64_t>::make({0, 1, 2, 3});

    auto b = v->begin();

    BOOST_REQUIRE_EQUAL(*(b + 0), 0);
    BOOST_REQUIRE_EQUAL(*(b + 1), 1);
    BOOST_REQUIRE_EQUAL(*(b + 2), 2);
    BOOST_REQUIRE_EQUAL(*(b + 3), 3);

    auto e = v->end();

    BOOST_REQUIRE((e - 0) == e);

    BOOST_REQUIRE_EQUAL(*(e - 1), 3);
    BOOST_REQUIRE_EQUAL(*(e - 2), 2);
    BOOST_REQUIRE_EQUAL(*(e - 3), 1);
    BOOST_REQUIRE_EQUAL(*(e - 4), 0);
}

BOOST_AUTO_TEST_CASE(ReverseIteratorArithmetic) {
    auto v = checker<int64_t>::make({0, 1, 2, 3});

    auto b = v->rbegin();

    BOOST_REQUIRE_EQUAL(*(b + 0), 3);
    BOOST_REQUIRE_EQUAL(*(b + 1), 2);
    BOOST_REQUIRE_EQUAL(*(b + 2), 1);
    BOOST_REQUIRE_EQUAL(*(b + 3), 0);

    auto e = v->rend();

    BOOST_REQUIRE((e - 0) == e);

    BOOST_REQUIRE_EQUAL(*(e - 1), 0);
    BOOST_REQUIRE_EQUAL(*(e - 2), 1);
    BOOST_REQUIRE_EQUAL(*(e - 3), 2);
    BOOST_REQUIRE_EQUAL(*(e - 4), 3);
}

BOOST_AUTO_TEST_CASE(IteratorCmp) {
    auto v = checker<int64_t>::make({0, 1, 2, 3});

    auto b = v->begin();

    BOOST_REQUIRE(b == b);
    BOOST_REQUIRE(b <= b);
    BOOST_REQUIRE(!(b < b));
    BOOST_REQUIRE(!(b > b));
    BOOST_REQUIRE(!(b != b));

    auto b1 = b + 1;

    BOOST_REQUIRE(b <= b1);
    BOOST_REQUIRE(b < b1);
    BOOST_REQUIRE(b1 >= b);
    BOOST_REQUIRE(b1 > b);
    BOOST_REQUIRE(b1 != b);
}

BOOST_AUTO_TEST_CASE(EmptyAfterMove) {
    // Checks that post move, the source vector is empty().
    // This is inline with std::vector guarantees.
    chunked_vector<int> v1;
    v1.push_back(1);
    BOOST_REQUIRE(!v1.empty());

    auto v2 = std::move(v1);
    // NOLINTNEXTLINE(bugprone-use-after-move)
    BOOST_REQUIRE(v1.empty());
    BOOST_REQUIRE(v1.begin() == v1.end());

    auto v3(std::move(v2));
    // NOLINTNEXTLINE(bugprone-use-after-move)
    BOOST_REQUIRE(v2.empty());
    BOOST_REQUIRE(v2.begin() == v2.end());
}

BOOST_AUTO_TEST_CASE(Sort) {
    vec v;
    v.push_back(3);
    v.push_back(2);
    v.push_back(1);

    std::sort(v.begin(), v.end());

    BOOST_REQUIRE(std::ranges::equal(v, std::vector<int>{1, 2, 3}));
}

BOOST_AUTO_TEST_CASE(Heap) {
    vec v{1, 2, 3};
    std::ranges::make_heap(v);
    BOOST_REQUIRE(std::ranges::is_heap(v));
}

BOOST_AUTO_TEST_CASE(Clear) {
    auto v = checker<int>::make({});
    BOOST_REQUIRE_EQUAL(v->size(), 0u);
    v->push_back(3);
    BOOST_REQUIRE_EQUAL(v->size(), 1u);
    v->push_back(2);
    BOOST_REQUIRE_EQUAL(v->size(), 2u);
    v->push_back(1);
    BOOST_REQUIRE_EQUAL(v->size(), 3u);
    v->clear();
    BOOST_REQUIRE(v.get() == vec{});
    BOOST_REQUIRE_EQUAL(v->size(), 0u);
    BOOST_REQUIRE(v.get().empty());
    v = checker<int>::make({5, 5, 5, 5});
    BOOST_REQUIRE_EQUAL(v->size(), 4u);
}

BOOST_AUTO_TEST_CASE(PopBackN) {
    const int elements = 6;
    for (int i = 0; i <= elements; ++i) {
        std::vector<int> start_values(elements);
        std::iota(start_values.begin(), start_values.end(), 0);
        auto vec = checker<int>::make(start_values);

        vec->pop_back_n(i);

        std::vector<int> expected_values(elements - i);
        std::iota(expected_values.begin(), expected_values.end(), 0);
        BOOST_REQUIRE_EQUAL(vec->size(), expected_values.size());
        BOOST_REQUIRE(std::ranges::equal(vec.get(), expected_values));

        if (elements - i > 0) {
            BOOST_REQUIRE_EQUAL(vec->back(), expected_values.back());
        }
    }
}

BOOST_AUTO_TEST_CASE(EraseToEnd) {
    chunked_vector<char> v;

    ASSERT_VALID(v);

    v.erase_to_end(v.begin());
    ASSERT_VALID(v);
    BOOST_REQUIRE_EQUAL(v.size(), 0u);

    v.erase_to_end(v.end());
    ASSERT_VALID(v);
    BOOST_REQUIRE_EQUAL(v.size(), 0u);

    v.push_back(0);
    v.erase_to_end(v.end());
    BOOST_REQUIRE(std::ranges::equal(v, std::vector<char>{0}));
    v.erase_to_end(v.begin());
    BOOST_REQUIRE(v.empty());

    v.push_back(0);
    v.push_back(1);
    v.push_back(2);
    v.push_back(3);
    BOOST_REQUIRE(std::ranges::equal(v, std::vector<char>{0, 1, 2, 3}));
    v.erase_to_end(v.begin() + 1);
    BOOST_REQUIRE(std::ranges::equal(v, std::vector<char>{0}));
}

BOOST_AUTO_TEST_CASE(FromIterRangeConstructor) {
    std::vector<int> vals{1, 2, 3};

    chunked_vector<int> fv(vals.begin(), vals.end());

    ASSERT_VALID(fv);
    BOOST_REQUIRE(std::ranges::equal(fv, std::vector<int>{1, 2, 3}));
}

BOOST_AUTO_TEST_CASE(FromInitializerListConstructor) {
    {
        chunked_vector<int> fv({});

        ASSERT_VALID(fv);
        BOOST_REQUIRE(fv.empty());
    }

    {
        chunked_vector<int> fv({1, 2, 3});

        ASSERT_VALID(fv);
        BOOST_REQUIRE(std::ranges::equal(fv, std::vector<int>{1, 2, 3}));
    }

    {
        chunked_vector<int> fv({1, 2, 3});

        ASSERT_VALID(fv);
        BOOST_REQUIRE(std::ranges::equal(fv, std::vector<int>{1, 2, 3}));
        // chunked_vector should have a "tight" capacity when constructed
        // from a list
        BOOST_REQUIRE_EQUAL(fv.capacity(), 3u);
    }
}

BOOST_AUTO_TEST_CASE(ChunkedVectorPushPop) {
    for (int i = 0; i < 100; ++i) {
        chunked_vector<int32_t> vec;
        for (size_t j = 0; j < vec.elements_per_fragment(); ++j) {
            bool push_back = vec.empty() || bool(get_int(1));
            if (push_back) {
                vec.push_back(j);
            } else {
                vec.pop_back();
            }
            ASSERT_VALID(vec);
        }
    }
}

BOOST_AUTO_TEST_CASE(ChunkedVectorPushPopN) {
    for (int i = 0; i < 100; ++i) {
        chunked_vector<int32_t> vec;
        for (size_t j = 0; j < vec.elements_per_fragment(); ++j) {
            // Slight preference to make larger vectors because we could be
            // popping back multiple
            switch (get_int(4)) {
            case 0:
            case 1:
            case 2:
                vec.push_back(j);
                break;
            case 3:
                vec.pop_back_n(get_int(vec.size()));
                break;
            case 4:
                vec.erase_to_end(vec.begin() + get_int(vec.size()));
                break;
            }

            ASSERT_VALID(vec);
        }
    }
}

BOOST_AUTO_TEST_CASE(FirstChunkCapacityDoubles) {
    chunked_vector<int32_t> vec;
    for (size_t i = 0; i < vec.elements_per_fragment(); ++i) {
        vec.push_back(i);
        ASSERT_VALID(vec);
    }
}

BOOST_AUTO_TEST_CASE(ReserveAndPushBack) {
    chunked_vector<int32_t> vec;
    vec.reserve(vec.elements_per_fragment());
    vec.push_back(-1);
    int* initial_location = &vec.front();
    for (size_t i = 0; i < vec.elements_per_fragment(); ++i) {
        vec.push_back(i);
        BOOST_REQUIRE_EQUAL(initial_location, &vec.front());
    }
}

BOOST_AUTO_TEST_CASE(Reserve) {
    chunked_vector<int32_t> growing_vec;
    for (size_t i = 0; i < chunked_vector<int32_t>::elements_per_fragment();
         ++i) {
        growing_vec.reserve(i);
        BOOST_REQUIRE_EQUAL(growing_vec.capacity(), i);
        ASSERT_VALID(growing_vec);
        // Also ensure "jumping" to that reserved size does the right thing.
        chunked_vector<int32_t> new_vec;
        new_vec.reserve(i);
        BOOST_REQUIRE_EQUAL(new_vec.capacity(), i);
        ASSERT_VALID(new_vec);
    }
}

BOOST_AUTO_TEST_CASE(ShrinkToFit) {
    chunked_vector<int32_t> vec;
    vec.reserve(32);
    ASSERT_VALID(vec);
    for (int i = 0; i < 10; ++i) {
        vec.push_back(1);
        ASSERT_VALID(vec);
    }
    vec.shrink_to_fit();
    ASSERT_VALID(vec);
    BOOST_REQUIRE_EQUAL(vec.capacity(), 10u);
}

BOOST_AUTO_TEST_CASE(InPlaceSingleElement) {
    auto v = chunked_vector<std::pair<seastar::sstring, int32_t>>::single(
      "a2", 3);
    BOOST_REQUIRE_EQUAL(v.size(), 1u);
    BOOST_REQUIRE(v[0].first == "a2");
    BOOST_REQUIRE_EQUAL(v[0].second, 3);
}

} // namespace
