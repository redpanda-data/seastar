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
 * Copyright (C) 2026 Redpanda Data
 */

#include <seastar/core/chunked_vector.hh>
#include <seastar/testing/perf_tests.hh>

#include <memory>
#include <vector>
#include <stdexcept>

using namespace seastar;

namespace {

// Each timed region runs this many operations, to amortize the cost of
// starting and stopping the clock.
constexpr size_t ops_per_run = 10000;

// Fits in the first, vector-like fragment.
constexpr size_t small_size = 4;
// Spans several full fragments (an int fragment holds 32Ki elements).
constexpr size_t big_size = 100000;

using trivial_elem = int;

// Counts every destructor call of nontrivial_elem, so the benches can check
// that moving a vector never touches its elements.
size_t nontrivial_dtor_count = 0;

// An element whose destructor the compiler cannot see through or elide: it is
// out of line and has a side effect on a global, so any destruction the
// container does is paid for and observable.
struct nontrivial_elem {
    nontrivial_elem(int x) noexcept : x(x) {}
    nontrivial_elem(const nontrivial_elem&) = default;
    nontrivial_elem(nontrivial_elem&&) noexcept = default;
    nontrivial_elem& operator=(const nontrivial_elem&) = default;
    nontrivial_elem& operator=(nontrivial_elem&&) noexcept = default;
    [[gnu::noinline]] ~nontrivial_elem();
    int x;
};

nontrivial_elem::~nontrivial_elem() {
    ++nontrivial_dtor_count;
    perf_tests::do_not_optimize(x);
}

template<typename T>
chunked_vector<T> make_n(size_t size) {
    chunked_vector<T> v;
    v.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        v.push_back(T(static_cast<int>(i)));
    }
    return v;
}

// Holds storage for two vectors so a bench can drive the move constructor
// directly, without a move assignment mixed in. Each vector lives in its own
// anonymous union, so its lifetime is managed by hand: only _a is live on
// construction and destruction.
template<typename T>
struct vector_pair {
    using vec = chunked_vector<T>;

    /**
     * @brief Constructs _a holding @p size elements; _b starts dead.
     */
    explicit vector_pair(size_t size) { std::construct_at(&_a, make_n<T>(size)); }

    /**
     * @brief Destroys _a, which the benches leave as the live vector.
     */
    ~vector_pair() { std::destroy_at(&_a); }

    /**
     * @brief Address of the first slot, valid whether or not it is live.
     */
    vec* a() { return &_a; }

    /**
     * @brief Address of the second slot, valid whether or not it is live.
     */
    vec* b() { return &_b; }

    union { vec _a; };
    union { vec _b; };
};

void check_no_dtors(size_t before) {
    if (nontrivial_dtor_count != before) {
        throw std::runtime_error("moving a chunked_vector destroyed elements");
    }
}

// Move-constructs the vector back and forth between two slots, destroying
// the moved-from source each time, the way std::vector reallocation or a
// return by value would. Each op is one move construction plus one
// destruction of an empty vector.
template<typename T>
size_t move_construct_bench(size_t size) {
    vector_pair<T> p(size);
    auto dtors = nontrivial_dtor_count;

    perf_tests::start_measuring_time();
    for (size_t i = 0; i < ops_per_run / 2; ++i) {
        std::construct_at(p.b(), std::move(*p.a()));
        std::destroy_at(p.a());
        perf_tests::do_not_optimize(*p.b());
        std::construct_at(p.a(), std::move(*p.b()));
        std::destroy_at(p.b());
        perf_tests::do_not_optimize(*p.a());
    }
    perf_tests::stop_measuring_time();

    check_no_dtors(dtors);
    return ops_per_run;
}

// Move-constructs into dst from src. Out of line so the move is compiled
// without knowledge of the surrounding code, as at most real call sites.
template<typename T>
[[gnu::noinline]] void move_construct_into(chunked_vector<T>* dst, chunked_vector<T>& src) {
    std::construct_at(dst, std::move(src));
}

// As move_construct_bench, but every move goes through move_construct_into.
template<typename T>
size_t move_construct_noinline_bench(size_t size) {
    vector_pair<T> p(size);
    auto dtors = nontrivial_dtor_count;

    perf_tests::start_measuring_time();
    for (size_t i = 0; i < ops_per_run / 2; ++i) {
        move_construct_into(p.b(), *p.a());
        std::destroy_at(p.a());
        move_construct_into(p.a(), *p.b());
        std::destroy_at(p.b());
    }
    perf_tests::stop_measuring_time();

    check_no_dtors(dtors);
    return ops_per_run;
}

// Grows a full std::vector of chunked_vectors by one element, so the
// reallocation moves every existing chunked_vector to the new buffer. Each op
// is one element relocation.
template<typename T>
size_t vector_realloc_bench(size_t size) {
    constexpr size_t count = 10000;
    std::vector<chunked_vector<T>> v;
    v.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        v.push_back(make_n<T>(size));
    }
    auto dtors = nontrivial_dtor_count;

    perf_tests::start_measuring_time();
    v.emplace_back();
    perf_tests::stop_measuring_time();

    perf_tests::do_not_optimize(v);
    check_no_dtors(dtors);
    return count;
}

// Move-assigns the vector back and forth between two live vectors. The
// target is always the empty, moved-from one.
template<typename T>
size_t move_assign_bench(size_t size) {
    auto a = make_n<T>(size);
    chunked_vector<T> b;
    auto dtors = nontrivial_dtor_count;

    perf_tests::start_measuring_time();
    for (size_t i = 0; i < ops_per_run / 2; ++i) {
        b = std::move(a);
        perf_tests::do_not_optimize(b);
        a = std::move(b);
        perf_tests::do_not_optimize(a);
    }
    perf_tests::stop_measuring_time();

    check_no_dtors(dtors);
    return ops_per_run;
}

struct chunked_vector_perf {};

} // namespace

PERF_TEST_F(chunked_vector_perf, move_construct_empty_trivial) {
    return move_construct_bench<trivial_elem>(0);
}

PERF_TEST_F(chunked_vector_perf, move_construct_small_trivial) {
    return move_construct_bench<trivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, move_construct_big_trivial) {
    return move_construct_bench<trivial_elem>(big_size);
}

PERF_TEST_F(chunked_vector_perf, move_construct_small_nontrivial) {
    return move_construct_bench<nontrivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, move_construct_big_nontrivial) {
    return move_construct_bench<nontrivial_elem>(big_size);
}

PERF_TEST_F(chunked_vector_perf, move_construct_noinline_small_trivial) {
    return move_construct_noinline_bench<trivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, move_construct_noinline_small_nontrivial) {
    return move_construct_noinline_bench<nontrivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, vector_realloc_small_trivial) {
    return vector_realloc_bench<trivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, vector_realloc_small_nontrivial) {
    return vector_realloc_bench<nontrivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, move_assign_small_trivial) {
    return move_assign_bench<trivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, move_assign_big_trivial) {
    return move_assign_bench<trivial_elem>(big_size);
}

PERF_TEST_F(chunked_vector_perf, move_assign_small_nontrivial) {
    return move_assign_bench<nontrivial_elem>(small_size);
}

PERF_TEST_F(chunked_vector_perf, move_assign_big_nontrivial) {
    return move_assign_bench<nontrivial_elem>(big_size);
}
