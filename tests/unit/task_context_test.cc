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
 * Copyright 2025 Redpanda Data, Inc.
 */

#include <seastar/core/coroutine.hh>
#include <seastar/core/future-util.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/task.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/when_any.hh>
#include <seastar/core/with_context.hh>
#include <seastar/coroutine/as_future.hh>
#include <seastar/coroutine/maybe_yield.hh>
#include <seastar/coroutine/switch_to.hh>
#include <seastar/coroutine/try_future.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/util/later.hh>

using namespace seastar;

#ifdef SEASTAR_TASK_CONTEXT

namespace {

struct test_context : task_context {
    int value = 0;
    explicit test_context(int v) : value(v) {}
};

test_context* current_test_context() {
    return static_cast<test_context*>(current_task_context());
}

lw_shared_ptr<task_context> make_test_ctx(int value) {
    return (new test_context(value))->shared_from_this();
}

} // anonymous namespace

// TLS starts cleared on entry to a fresh task.
SEASTAR_TEST_CASE(test_context_default_null) {
    BOOST_REQUIRE(!current_task_context());
    return make_ready_future<>();
}

// Direct set/get on a task's _context via the public accessors.
SEASTAR_TEST_CASE(test_context_task_set_and_get) {
    auto* t = engine().current_task();
    auto ctx = make_test_ctx(42);
    t->set_context(ctx);
    BOOST_REQUIRE_EQUAL(t->context_ptr(), ctx.get());
    t->set_context({});
    BOOST_REQUIRE(!t->context_ptr());
    return make_ready_future<>();
}

// Direct set/get on TLS via the public accessors.
SEASTAR_TEST_CASE(test_context_tls_set_and_get) {
    auto ctx = make_test_ctx(7);
    set_current_task_context(ctx.get());
    BOOST_REQUIRE_EQUAL(current_task_context(), ctx.get());
    set_current_task_context(nullptr);
    BOOST_REQUIRE(!current_task_context());
    return make_ready_future<>();
}

// lw_shared_ptr refcount semantics on task._context.
SEASTAR_TEST_CASE(test_context_refcount) {
    auto* raw = new test_context(600);
    auto ctx = raw->shared_from_this();
    BOOST_REQUIRE_EQUAL(raw->use_count(), 1);

    engine().current_task()->set_context(ctx);
    BOOST_REQUIRE_EQUAL(raw->use_count(), 2);

    engine().current_task()->set_context({});
    BOOST_REQUIRE_EQUAL(raw->use_count(), 1);

    return make_ready_future<>();
}

// Polymorphic deletion via virtual destructor on task_context.
SEASTAR_TEST_CASE(test_context_virtual_destructor) {
    bool destroyed = false;

    struct destructor_tracker : task_context {
        bool& flag;
        explicit destructor_tracker(bool& f) : flag(f) {}
        ~destructor_tracker() override { flag = true; }
    };

    {
        auto* raw = new destructor_tracker(destroyed);
        auto ctx = raw->shared_from_this();
        BOOST_REQUIRE(!destroyed);
    }
    BOOST_REQUIRE(destroyed);
    return make_ready_future<>();
}

// with_context installs ctx as TLS while func runs. Inline children
// inherit ctx via task construction.
SEASTAR_TEST_CASE(test_with_context_installs_tls_during_func) {
    auto ctx = make_test_ctx(1);
    BOOST_REQUIRE(!current_task_context());
    co_await with_context(ctx, [] () -> future<> {
        BOOST_REQUIRE(current_test_context());
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1);
        co_return;
    });
    BOOST_REQUIRE(!current_task_context());
}

// If func is a coroutine, its promise is constructed with TLS=ctx,
// so promise._context=ctx from birth. Suspension + resume reads
// promise._context, so TLS comes back as ctx on resume.
SEASTAR_TEST_CASE(test_with_context_survives_co_await_in_func) {
    auto ctx = make_test_ctx(2);
    co_await with_context(ctx, [] () -> future<> {
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 2);
        co_await coroutine::maybe_yield();
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 2);
        co_await yield();
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 2);
    });
    BOOST_REQUIRE(!current_task_context());
}

// .then() continuations created inside func inherit ctx at
// construction via TLS, so they propagate correctly even after
// with_context returns.
SEASTAR_TEST_CASE(test_with_context_then_chain_inherits) {
    auto ctx = make_test_ctx(3);
    co_await with_context(ctx, [] {
        return yield().then([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 3);
        }).then([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 3);
        });
    });
    BOOST_REQUIRE(!current_task_context());
}

// with_context must not modify the current task's _context, otherwise
// long-lived driver tasks would leak context across iterations.
SEASTAR_TEST_CASE(test_with_context_does_not_pollute_current_task) {
    auto* t = engine().current_task();
    auto original = t->context_ptr();
    auto ctx = make_test_ctx(4);
    co_await with_context(ctx, [] () -> future<> {
        co_return;
    });
    BOOST_REQUIRE_EQUAL(t->context_ptr(), original);
    BOOST_REQUIRE(!current_task_context());
}

SEASTAR_TEST_CASE(test_with_context_nested) {
    auto outer = make_test_ctx(10);
    auto inner = make_test_ctx(20);
    co_await with_context(outer, [inner] () -> future<> {
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 10);
        co_await with_context(inner, [] () -> future<> {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 20);
            co_await coroutine::maybe_yield();
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 20);
        });
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 10);
    });
    BOOST_REQUIRE(!current_task_context());
}

SEASTAR_TEST_CASE(test_with_context_restores_tls_on_exception) {
    auto ctx = make_test_ctx(5);
    try {
        co_await with_context(ctx, [] () -> future<> {
            throw std::runtime_error("oops");
            co_return;
        });
        BOOST_FAIL("expected exception");
    } catch (const std::runtime_error&) {
        // expected
    }
    BOOST_REQUIRE(!current_task_context());
}

// Passing an empty context clears TLS for the duration of func,
// then restores it on return.
SEASTAR_TEST_CASE(test_with_context_empty_ctx) {
    auto outer = make_test_ctx(99);
    co_await with_context(outer, [] () -> future<> {
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 99);
        co_await with_context(lw_shared_ptr<task_context>{}, [] () -> future<> {
            BOOST_REQUIRE(!current_task_context());
            co_return;
        });
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 99);
    });
    BOOST_REQUIRE(!current_task_context());
}

// parallel_for_each sub-task branches see the enclosing context.
// Regression for the set_current_task sync added to ensure inline
// resumption via parallel_for_each doesn't drop TLS.
SEASTAR_TEST_CASE(test_with_context_parallel_for_each) {
    auto ctx = make_test_ctx(6);
    co_await with_context(ctx, [] () -> future<> {
        std::vector<int> items{1, 2, 3};
        co_await parallel_for_each(items, [] (int) -> future<> {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 6);
            co_return;
        });
    });
    BOOST_REQUIRE(!current_task_context());
}

// Context propagates into with_gate lambdas.
SEASTAR_TEST_CASE(test_with_context_gate) {
    auto ctx = make_test_ctx(500);
    co_await with_context(ctx, [] () -> future<> {
        gate g;
        auto holder = g.hold();
        auto f = with_gate(g, [] () -> future<> {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 500);
            return make_ready_future<>();
        });
        co_await std::move(f);
        holder.release();
        co_await g.close();
    });
    BOOST_REQUIRE(!current_task_context());
}

// Context propagates into seastar::async.
SEASTAR_TEST_CASE(test_with_context_async) {
    auto ctx = make_test_ctx(400);
    co_await with_context(ctx, [] () -> future<> {
        co_await async([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 400);
        });
    });
    BOOST_REQUIRE(!current_task_context());
}

// Context does NOT cross shards: lw_shared_ptr is not thread-safe,
// and work_item uses no_context_tag to avoid inheriting.
SEASTAR_TEST_CASE(test_context_does_not_propagate_across_shards) {
    if (smp::count < 2) {
        co_return;
    }

    auto ctx = make_test_ctx(300);
    co_await with_context(ctx, [] () -> future<> {
        auto other_shard = (this_shard_id() + 1) % smp::count;
        bool remote_has_context = co_await smp::submit_to(other_shard, [] {
            auto* t = engine().current_task();
            return t && t->context_ptr() != nullptr;
        });
        BOOST_REQUIRE(!remote_has_context);
    });
}

// A child task's captured lw_shared_ptr keeps the context alive
// after with_context returns. The child task's own _context owns a
// reference from its construction.
SEASTAR_TEST_CASE(test_context_child_outlives_caller) {
    promise<> p;
    auto f = make_ready_future<>();

    co_await with_context(make_test_ctx(42), [&] () -> future<> {
        f = p.get_future().then([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 42);
        });
        co_return;
    });
    // TLS restored after with_context returns.
    BOOST_REQUIRE(!current_task_context());
    p.set_value();
    co_await std::move(f);
}

// Clearing the TLS mid-execution stops propagation to subsequently
// created tasks.
SEASTAR_TEST_CASE(test_context_clear_stops_propagation) {
    auto ctx = make_test_ctx(700);
    co_await with_context(ctx, [] () -> future<> {
        set_current_task_context(nullptr);
        co_await yield().then([] {
            BOOST_REQUIRE(!current_test_context());
        });
    });
}

// Clearing context mid-.then() chain does NOT affect subsequent
// continuations because they inherited at construction time.
// Fixing this would require schedule-time propagation in add_task,
// which causes cross-contamination from unrelated promise resolvers.
SEASTAR_TEST_CASE(test_context_clear_mid_then_chain_does_not_propagate) {
    auto ctx = make_test_ctx(800);
    return with_context(ctx, [] {
        return yield().then([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 800);
            set_current_task_context(nullptr);
        }).then([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 800);
        });
    });
}

// All when_any branches share the same context object via pointer
// identity. Context stays alive while any branch holds a reference.
SEASTAR_TEST_CASE(test_context_when_any) {
    auto* raw = new test_context(1100);
    auto ctx = raw->shared_from_this();

    co_await with_context(ctx, [raw] () -> future<> {
        promise<int> p1;
        promise<int> p2;

        auto f1 = p1.get_future().then([raw] (int v) {
            BOOST_REQUIRE_EQUAL(current_test_context(), raw);
            return v;
        });
        auto f2 = p2.get_future().then([raw] (int v) {
            BOOST_REQUIRE_EQUAL(current_test_context(), raw);
            return v;
        });

        auto any = when_any(std::move(f1), std::move(f2));
        p1.set_value(10);
        auto result = co_await std::move(any);
        (void)result;
        p2.set_value(20);
    });
}

// Context survives an I/O completion (sleep-based here).
SEASTAR_TEST_CASE(test_context_survives_io_completion) {
    auto ctx = make_test_ctx(1200);
    co_await with_context(ctx, [] () -> future<> {
        co_await sleep(std::chrono::milliseconds(1));
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1200);
    });
}

// Context persists through a not-ready future (set_coroutine path).
SEASTAR_TEST_CASE(test_context_awaiter_not_ready) {
    auto ctx = make_test_ctx(1300);
    co_await with_context(ctx, [] () -> future<> {
        co_await yield();
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1300);
    });
}

// Context persists through a ready future (preemption/schedule path).
SEASTAR_TEST_CASE(test_context_awaiter_ready_preempt) {
    auto ctx = make_test_ctx(1400);
    co_await with_context(ctx, [] () -> future<> {
        co_await make_ready_future<>();
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1400);
    });
}

// Context persists through coroutine::as_future with a not-ready future.
SEASTAR_TEST_CASE(test_context_as_future_not_ready) {
    auto ctx = make_test_ctx(1500);
    co_await with_context(ctx, [] () -> future<> {
        auto f = co_await coroutine::as_future(yield().then([] { return 42; }));
        BOOST_REQUIRE(!f.failed());
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1500);
    });
}

// Context persists through coroutine::as_future with a ready future.
SEASTAR_TEST_CASE(test_context_as_future_ready) {
    auto ctx = make_test_ctx(1600);
    co_await with_context(ctx, [] () -> future<> {
        auto f = co_await coroutine::as_future(make_ready_future<int>(42));
        BOOST_REQUIRE(!f.failed());
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1600);
    });
}

// Context persists through coroutine::maybe_yield.
SEASTAR_TEST_CASE(test_context_maybe_yield) {
    auto ctx = make_test_ctx(1700);
    co_await with_context(ctx, [] () -> future<> {
        co_await coroutine::maybe_yield();
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1700);
    });
}

// Context persists across scheduling group switches.
SEASTAR_TEST_CASE(test_context_switch_to) {
    auto ctx = make_test_ctx(1800);
    co_await with_context(ctx, [] () -> future<> {
        auto sg = co_await create_scheduling_group("test_ctx_sg", 100);
        auto prev_sg = co_await coroutine::switch_to(sg);
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1800);
        co_await coroutine::switch_to(prev_sg);
        co_await destroy_scheduling_group(sg);
    });
}

// Context persists through coroutine::try_future with a not-ready
// future.
SEASTAR_TEST_CASE(test_context_try_future_not_ready) {
    auto ctx = make_test_ctx(1900);
    co_await with_context(ctx, [] () -> future<> {
        co_await coroutine::try_future(yield().then([] { return 42; }));
        BOOST_REQUIRE_EQUAL(current_test_context()->value, 1900);
    });
}

// parallel_for_each resumes coroutines via set_current_task, not
// through the reactor loop. Regression for the TLS sync in
// set_current_task.
SEASTAR_TEST_CASE(test_context_parallel_for_each_set_current_task) {
    auto ctx = make_test_ctx(2000);
    co_await with_context(ctx, [] () -> future<> {
        std::vector<int> items{1, 2, 3};
        co_await parallel_for_each(items, [] (int) -> future<> {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 2000);
            co_await yield();
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 2000);
        });
    });
}

// thread_context::switch_in calls set_current_task(nullptr). After
// a blocking .get() inside async, TLS must reflect the null state.
// Regression for the thread.cc sync.
SEASTAR_TEST_CASE(test_context_async_after_blocking_get) {
    auto ctx = make_test_ctx(2100);
    co_await with_context(ctx, [] () -> future<> {
        co_await async([] {
            BOOST_REQUIRE_EQUAL(current_test_context()->value, 2100);
            yield().get();
            // After .get() resumes, set_current_task(nullptr) was called.
            // TLS should be null.
            BOOST_REQUIRE(!current_test_context());
        });
    });
}

// do_with keeps a with_context-wrapped continuation chain alive.
SEASTAR_TEST_CASE(test_with_context_do_with_chain) {
    auto ctx = make_test_ctx(1000);
    return with_context(ctx, [] {
        return do_with(int{0}, [] (int& counter) {
            return yield().then([&counter] {
                BOOST_REQUIRE_EQUAL(current_test_context()->value, 1000);
                ++counter;
            }).then([&counter] {
                BOOST_REQUIRE_EQUAL(current_test_context()->value, 1000);
                ++counter;
                BOOST_REQUIRE_EQUAL(counter, 2);
            });
        });
    });
}

#else // !SEASTAR_TASK_CONTEXT

// When disabled, accessors compile and return null.
SEASTAR_TEST_CASE(test_context_noop_when_disabled) {
    auto* t = engine().current_task();
    BOOST_REQUIRE(t);
    BOOST_REQUIRE(!t->context_ptr());
    t->set_context({});
    BOOST_REQUIRE(!current_task_context());
    set_current_task_context(nullptr);
    return make_ready_future<>();
}

#endif // SEASTAR_TASK_CONTEXT
