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
 * Copyright (C) 2018 ScyllaDB
 */

#pragma once



#if __has_include(<memory_resource>)
#include <memory_resource>
#else
#include <experimental/memory_resource>
namespace std::pmr {
    using namespace std::experimental::pmr;
}
#endif

#include <source_location>

// Defining SEASTAR_ASAN_ENABLED in here is a bit of a hack, but
// convenient since it is build system independent and in practice
// everything includes this header.

#ifndef __has_feature
#define __has_feature(x) 0
#endif

// clang uses __has_feature, gcc defines __SANITIZE_ADDRESS__
#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define SEASTAR_ASAN_ENABLED
#endif

namespace seastar::compat {

// Deprecated: use std::source_location directly.
// This alias is maintained for backwards compatibility with external users.
using source_location
    [[deprecated("Use std::source_location instead of seastar::compat::source_location")]]
    = std::source_location;

}

#if defined(__GNUC__) && !defined(__clang__)
// GCC Workaround: Strip source_location to prevent ICE during RTL expansion.
// See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=114675
#define SEASTAR_COROUTINE_LOC_PARAM
#define SEASTAR_COROUTINE_LOC_STORE(promise) (void)0
#else
// Standard/Clang: Capture source location naturally.
// Includes the leading comma to mix cleanly into argument lists.
#define SEASTAR_COROUTINE_LOC_PARAM \
    , std::source_location sl = std::source_location::current()

#define SEASTAR_COROUTINE_LOC_STORE(promise) \
    (promise).update_resume_point(sl)
#endif

// Coroutine HALO (Heap Allocation eLision Optimization) support.
//
// These macros gate LLVM attributes that enable the compiler to elide
// coroutine frame heap allocations when a coroutine is directly co_await-ed
// in another coroutine:
//
//  - SEASTAR_CORO_AWAIT_ELIDABLE: placed on the coroutine return type
//    (e.g. future<T>). Tells the compiler that a coroutine returning this
//    type can have its frame allocation elided when it is directly
//    co_await-ed inside another coroutine.
//
//  - SEASTAR_CORO_ONLY_DESTROY_WHEN_COMPLETE: placed on the promise_type.
//    Asserts that the coroutine will only be destroyed after running to
//    completion (i.e. after reaching final_suspend). This is naturally
//    true for Seastar coroutines whose final_suspend returns suspend_never,
//    because the coroutine frame is implicitly destroyed upon completion.
//    The annotation lets the compiler generate a simpler destroy path and
//    is a prerequisite for safe await-elision.
//
// See also: Folly's FOLLY_ATTR_CLANG_CORO_AWAIT_ELIDABLE in CppAttributes.h
// and the LLVM coroutine HALO RFC.
#if defined(__has_cpp_attribute)
  #if __has_cpp_attribute(clang::coro_await_elidable)
    #define SEASTAR_CORO_AWAIT_ELIDABLE [[clang::coro_await_elidable]]
  #else
    #define SEASTAR_CORO_AWAIT_ELIDABLE
  #endif

  #if __has_cpp_attribute(clang::coro_only_destroy_when_complete)
    #define SEASTAR_CORO_ONLY_DESTROY_WHEN_COMPLETE [[clang::coro_only_destroy_when_complete]]
  #else
    #define SEASTAR_CORO_ONLY_DESTROY_WHEN_COMPLETE
  #endif

  #if __has_cpp_attribute(clang::coro_await_elidable_argument)
    #define SEASTAR_CORO_AWAIT_ELIDABLE_ARGUMENT [[clang::coro_await_elidable_argument]]
  #else
    #define SEASTAR_CORO_AWAIT_ELIDABLE_ARGUMENT
  #endif
#else
  #define SEASTAR_CORO_AWAIT_ELIDABLE
  #define SEASTAR_CORO_ONLY_DESTROY_WHEN_COMPLETE
  #define SEASTAR_CORO_AWAIT_ELIDABLE_ARGUMENT
#endif
