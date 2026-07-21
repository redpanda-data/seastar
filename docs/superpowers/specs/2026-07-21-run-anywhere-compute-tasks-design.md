# Run-anywhere compute tasks

Date: 2026-07-21 · Status: draft for review · Scope: design only (no implementation yet)

## Problem

Seastar workloads are shard-affine: every task, future, and continuation belongs to
the core that created it. That is the right model for I/O and state, but it leaves no
good home for CPU-heavy batch work (checksums, compression, compaction-style
computation). Today such work either monopolizes its home shard or must be manually
sharded by the application.

We want a task type with the opposite affinity contract:

- **Runs anywhere.** It may execute on any shard that has spare CPU, and may migrate
  between shards over its lifetime.
- **Strictly lower priority.** It only consumes cycles a shard would otherwise waste;
  it never competes with normal seastar tasks.
- **Isolated.** It may not touch shard-affine seastar machinery (futures, promises,
  `engine()`, timers, I/O) while running — that machinery is what makes migration
  unsafe.
- **Shard-affine edges.** `submit()` is called on a shard, and the returned
  `seastar::future` resolves (and its continuation runs) on that same shard. Only the
  compute task itself migrates.
- **Near-zero cost** to reactors that never use the feature, and to busy shards even
  when it is in use.

## High level design

Essentially these can be implemented as a new flavor of coroutine which is affine to a global task queue.

When any given seastar shard finds itself idle, it may check for globally promised work, pluck a task from it, run the task through to a suspension point, and then reevaluate its own idle state, yielding the 'run anywhere' task if it has shard local work to do.

Yielded 'run anywhere' tasks get kicked to the back of the global queue, and the newly busy shard burns down its shard local task queue exactly as is does today.

## Why this is feasible: the reactor already has the seam

When a full poll cycle finds nothing to do, the reactor's main loop invokes an
installable idle handler (`src/core/reactor.cc:3534`, types in
`include/seastar/core/idle_cpu_handler.hh`). The handler receives a poll predicate
that turns true the instant real work arrives, and its return value decides whether
the shard goes to sleep. This hook is unused in-tree, is unreachable from the busy
path, and its contract is exactly the scheduling behavior we need. "Idle" here is
*instantaneous*, not "idle all second": a shard at 30% utilization passes through this
branch thousands of times per second, so compute tasks naturally fill the gaps on
lightly loaded shards, not just on parked ones.

## API sketch

```c++
namespace seastar::compute {          // naming TBD

template <typename T>
class task;                           // coroutine type; deliberately NOT a seastar::task

// Must be called on a reactor thread. The returned future resolves on the
// calling shard; its continuations are ordinary shard-local continuations.
template <typename T>
future<T> submit(task<T> t);

// Cooperative scheduling point. No-op while the current shard is idle;
// otherwise re-queues this task globally and lets the shard resume normal work.
auto checkpoint();

}
```

```c++
compute::task<uint32_t> checksum(temporary_buffer<char> buf) {
    uint32_t acc = 0;
    for (size_t off = 0; off < buf.size(); off += chunk_size) {
        acc = crc32(acc, buf.get() + off, std::min(chunk_size, buf.size() - off));
        co_await compute::checkpoint();     // may resume on a different shard
    }
    co_return acc;
}

future<uint32_t> f = compute::submit(checksum(std::move(buf)));
```

## How it works, end to end

1. **Submit.** The caller hands a compute task to `compute::submit()` and gets back an
   ordinary shard-affine `seastar::future` on which to await the work, exactly as if
   it were local.
2. **Pull.** Any shard that finds itself idle pulls the task from the global queue and
   runs it.
3. **Checkpoint.** At each `co_await compute::checkpoint()` the task offers to give
   the CPU back: if the running shard now has shard-local work or other reactor duties,
   the task yields so the shard can get on with them; otherwise it just keeps running.
4. **Complete.** The result is kicked back to the caller's shard, where the future
   resolves and its continuation runs like any other.

The addendum at the end of this document walks the same lifecycle in full mechanical
detail.

## Checkpoint semantics

`co_await compute::checkpoint()` is the heart of the design; it has a fast path and
two distinct yield outcomes.

**Fast path.** The awaiter's `await_ready()` is simply `!need_preempt()` — two relaxed
loads of the preemption monitor, identical to seastar's existing
`coroutine::maybe_yield`. While it stays false the coroutine continues *inline*: no
suspension, no queue traffic, no allocation. `need_preempt()` is the right signal
because everything the shard must react to flips it, directly or within a bounded
delay: the task-quota timer stays armed on the idle branch (it is only disarmed
across actual sleep, `src/core/reactor.cc:3545`), so the monitor fires at least every
~0.5 ms; in the linux-aio backend the monitor *is* the kernel completion ring, so I/O
completions flip it instantly; and anything only a poller can discover (e.g. incoming
SMP messages) is picked up at the next quota tick — the same reaction bound normal
seastar tasks provide, since `run_tasks()` also only observes `need_preempt()`.

**Yield classification.** When the monitor fires, the coroutine suspends and control
returns to the per-shard participant, which evaluates the reactor's full
`pure_check_for_work` predicate to decide between two outcomes:

- *Housekeeping tick* (quota expired, but no foreground work): the handle is parked
  locally, the participant returns to the main loop for one iteration — pollers run,
  clocks update, the preemption monitor resets — and on the next idle-branch visit
  the same shard resumes the parked task. No global-queue round trip, no migration
  churn on an otherwise idle system.
- *Foreground work arrived*: the handle is pushed to the global queue (waking at most
  one parked shard, exactly like a fresh submit — otherwise a lone busy shard could
  strand a task while every other shard sleeps), and the participant reports
  "interrupted" so the reactor returns to normal duties immediately. If the
  foreground burst is brief and no other shard is idle, the same shard simply pops
  the task back on its next idle visit — the queue round trip is the only cost, and
  no migration actually happens.

**Publish-and-forget.** Once the handle is pushed, the frame belongs to whoever pops
it: another shard may resume it before the pushing shard has finished unwinding. The
push is therefore the awaiter's last touch of the frame (the awaiter object itself
lives inside the frame). The queue's release/acquire pair makes all frame writes from
the yielding shard visible to the resuming shard.

**Why cross-shard resumption is safe here.** A coroutine executes as a sequence of
resume segments, each of which runs entirely on one pthread; suspension spills all
live state into the heap frame, and resumption re-enters through fresh calls that
reload any thread-locals. The fiber killer — thread-local *addresses* cached in
registers or on the stack across the suspension — cannot survive a coroutine
suspension by construction. Two honest caveats: values the user copies across a
checkpoint (say, a stashed `this_shard_id()`) are legitimately stale, which the
isolation rules cover; and compilers must not cache thread-local reads across
suspension points — historical LLVM bugs in this area are long fixed, but a small
regression test is cheap insurance.

**Frequency guidance.** A no-op checkpoint costs a couple of relaxed loads, so it can
sit inside inner loops with bodies of a few hundred nanoseconds or more (stride it in
tighter loops). The latency a compute task imposes on newly arriving foreground work
equals the gap between checkpoints, so the contract is: aim for a few microseconds to
tens of microseconds of computation per checkpoint, and never more than a task quota.

## What compute-task code may and may not do

Allowed: pure computation; heap allocation; reading data the caller handed in by
value or via pointers that are safe to touch from any shard.

Not allowed (and mostly *not expressible*): `co_await` on a `seastar::future`,
creating or scheduling `seastar::task`s, `engine()`, timers, I/O, or anything else
shard-affine. Enforcement is layered:

- **Compile time (primary).** `compute::task<T>`'s promise type does not derive from
  `seastar::task` and defines awaiters only for the closed set of compute awaitables
  (`checkpoint()` in v1). `co_await some_future` does not compile inside one.
- **Debug runtime (backstop).** A thread-local "inside compute task" flag, asserted in
  `reactor::add_task` and friends under debug builds, catches direct calls into the
  reactor — the same pattern as the existing `SEASTAR_DEBUG_PROMISE` cross-shard
  tripwire (`src/core/future.cc:108`).

The contract also requires *cooperation*: checkpoint roughly every task-quota
(~0.5 ms) of computation. A chunk that computes for 10 ms between checkpoints adds
10 ms of latency to normal tasks that arrive meanwhile. The stall detector remains
armed while compute work runs, so gross violations are reported like any other stall.

## Reactor seam

One internal hook on the idle branch, adjacent to the existing idle-handler call. The
public `set_idle_cpu_handler()` remains untouched for downstream users.

```c++
// reactor::do_run(), idle branch (near src/core/reactor.cc:3534)
if (_compute_participant) {                                   // null unless feature initialized
    auto r = _compute_participant->run_some(pure_check_for_work);
    go_to_sleep &= (r == idle_cpu_handler_result::no_more_work);
}
```

`run_some()` loops: pop a task from the global queue, resume it until it completes or
checkpoints away, and between tasks re-test the poll predicate. It returns
"interrupted" when real work arrived (reactor resumes normal duties) and
"no more work" when the queue is empty (reactor proceeds toward sleep, after
registering this shard as wakeable — see below).

## Global queue and wake protocol

The queue is the one genuinely new shared structure in seastar: everything existing is
single-consumer (SMP rings are pairwise SPSC; the alien queue and cross-CPU freelist
are MPSC). v1 uses a `boost::lockfree::queue` (already the alien queue's foundation,
and MPMC-capable) fronted by a relaxed nonempty counter, so idle shards pay one relaxed
load per poll when there is no compute work. Contention is structurally low: consumers
only touch the queue when idle, producers only on submit and yield-back.

Sleep/wake reuses seastar's asymmetric-barrier scheme (`src/core/reactor.cc:3104`,
`3867`): a shard registers in a sleeper list before parking and rechecks the queue
after the systemwide barrier; a producer, after pushing, wakes at most one registered
sleeper via the existing `reactor::wakeup()` eventfd. Spurious wakeups are permitted
and harmless; lost wakeups are impossible (Dekker ordering, same as SMP submission).

## Performance impact

| Scenario | Cost |
|---|---|
| Feature never initialized | one null-pointer test on the idle branch; busy path untouched |
| Enabled, shard busy | zero — the seam is unreachable |
| Enabled, shard idle, queue empty | one relaxed load per idle iteration; registry work amortized over the sleep transition |
| Producers (submit / yield-back) | one CAS push, plus a relaxed sleeper-registry check |

Nothing changes in `run_some_tasks`, `add_task`, or `poll_once`; no new poller runs on
the hot loop.

## Observability

Time spent running compute tasks currently would be accounted as *idle*
(`_total_idle`); it gets its own bucket so utilization metrics stay honest. Add
metrics: global queue depth, tasks completed, yield-back migrations, per-shard compute
runtime.

## Testing

- Unit: submit/complete round trip across ≥2 shards; result and exception marshaling
  land on the submitting shard; yield-back under injected foreground load; resume
  after migration preserves frame state; wake-from-sleep when work is submitted to a
  fully parked system; debug tripwire fires on illegal reactor calls.
- Perf: confirm zero regression on the busy path with the feature off and on
  (existing perf suite), plus a microbenchmark of idle-loop overhead with the queue
  empty.

## Out of scope for v1 / open questions

- **Cancellation and shutdown drain.** v1 proposal: at reactor shutdown, tasks still
  queued are destroyed and their futures resolve as broken promises; no mid-flight
  cancellation API. Needs confirmation.
- **Backpressure.** v1 queue is unbounded with a depth metric; a bounded/deferred
  submit can come later.
- **Fairness among compute tasks.** In v1 an idle shard resumes its locally parked
  task in preference to pulling from the global queue, so a task effectively runs to
  completion or yield-back while queued compute tasks wait. The housekeeping tick is
  a natural rotation point if round-robin fairness is wanted later.
- **Utilization-threshold pulls.** Instantaneous-idle gating already serves lightly
  loaded shards (they hit the idle branch between bursts). A smoothed-load knob
  (e.g. only pull when 5s-average idle fraction exceeds X) is a possible later
  refinement, as is a forced-yield deadline per chunk.
- **NUMA locality.** Frames allocated on the home shard are accessed remotely while
  migrated. Acceptable for throughput-oriented batch work; revisit if it matters.

## Addendum: the lifecycle in full detail

The high-level steps above, replayed with every mechanism visible. Suppose a 4-shard
reactor where shard 3 submits a task while shards 0 and 1 are parked and shard 2 is
busy.

**Submit, on shard 3.** `compute::submit(my_task(...))` materializes the coroutine
frame; the frame records its home shard (3) and a handle to a `promise<T>` that lives
on shard 3 and never leaves it. The coroutine handle is pushed onto the global queue
(one CAS), and because the sleeper registry is non-empty, exactly one parked shard —
say shard 0 — is woken via its notify eventfd. The caller on shard 3 holds an
ordinary `future<T>`; nothing about it is special.

**Pull, on shard 0.** Shard 0 wakes, runs its main loop, finds no shard-local work,
and lands on the idle branch. Its compute participant sees the global queue's
nonempty flag (one relaxed load), pops the handle, and resumes the coroutine. The
task now executes on shard 0's reactor thread, in the gap the reactor would otherwise
have spent asleep.

**Checkpoints, on shard 0.** Every `co_await compute::checkpoint()` reads
`need_preempt()` — two relaxed loads — and continues inline while it stays false. Two
things can end the run (see *Checkpoint semantics* for the full treatment):

- A quota tick with no foreground work: the task parks locally, shard 0 makes one
  housekeeping trip around the main loop (pollers, clocks, monitor reset), then
  resumes the same task. No queue traffic, no migration.
- Foreground work arrives on shard 0 — say an SMP message lands: the handle goes back
  onto the global queue, another parked shard (shard 1) is woken to consider it, and
  the participant reports "interrupted" so shard 0 turns to its own work immediately.
  The latency shard 0's new work paid is bounded by the task's checkpoint gap.

**Migration, to shard 1.** Shard 1 pops the handle and resumes the frame mid-function
— the coroutine simply continues at the instruction after the checkpoint. The
release/acquire edge on the queue push/pop makes every frame write from shard 0
visible on shard 1. No stack, register, or TLS state crosses over; that is the
property that makes coroutines migratable where stackful fibers are not.

**Complete, back to shard 3.** The task `co_return`s on shard 1. The runtime — never
user code — marshals the value (or exception) to shard 3 over the existing
cross-shard messaging, the same completes-back-home shape `thread_pool` /
`syscall_work_queue` use for blocking syscalls (`src/core/thread_pool.cc`). Shard 3
fulfills the promise, and the caller's continuation runs there like any other.

**Teardown.** The frame is destroyed wherever the task finished (shard 1 here). The
allocator routes the cross-shard free back to the owning shard with a single CAS
(`src/core/memory.cc:1070`), so frames need no special lifetime handling.
