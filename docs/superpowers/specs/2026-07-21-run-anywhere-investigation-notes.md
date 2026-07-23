# Run-anywhere compute tasks — investigation notes

Companion to `2026-07-21-run-anywhere-compute-tasks-design.md`. These are the raw
findings from the feasibility investigation of the seastar reactor internals; the
design doc cites them selectively. File:line references are against branch
`run-anywhere-compute-tasks-design` (based on v26.2.x, July 2026).

## 1. Reactor main loop and the idle seam

- Main loop: `reactor::do_run()`, `src/core/reactor.cc:3394`; the loop body at
  `3508-3565`. Each iteration: `_cpu_sched.run_some_tasks()` → `check_for_work()`
  (`poll_once() || have_more_tasks()`) → if nothing, the **idle branch**.
- Idle branch (`3523-3563`): invokes `_idle_cpu_handler(pure_check_for_work)` at
  `3534`. `pure_check_for_work = pure_poll_once() || have_more_tasks()` — checks
  without performing work (comment at `3531-3533` explains why the pure variant).
  Handler returns `no_more_work` → reactor proceeds toward sleep;
  `interrupted_by_higher_priority_task` → reactor re-runs `check_for_work()` and
  loops. Handler exceptions are caught and reported (`3536-3538`).
- The idle handler seam (`include/seastar/core/idle_cpu_handler.hh`,
  `reactor::set_idle_cpu_handler` at `include/seastar/core/reactor.hh:657`) is
  **unused in-tree** — only declaration, default no-op, forwarding free function,
  and module export exist.
- Sleep gate: only after continuous idleness exceeds `_cfg.max_poll_time` (`3541`)
  does the reactor try `pollers_enter_interrupt_mode()` (`3542`, impl `3591`); any
  poller may refuse. The task-quota timer is disarmed across sleep (`3545`) and
  re-armed on wake (`3556`). The blocking wait is `wait_and_process_events()`
  (`3549` → backend).
- `have_more_tasks()` = `_cpu_sched.active()` = `_active.size() + _activating.size()`
  (`3206-3214`) — the O(1) "runnable seastar tasks exist" test.
- Load accounting: `_total_idle`/`_total_sleep` (`reactor.hh:367-368`); smoothed
  `_load` = 5-sample mean of per-second idle fraction, updated by a 1 Hz
  `_load_timer` (`reactor.cc:3462-3473`); no public accessor. `pending_task_count()`
  sums queue lengths (`reactor.cc:2680`).
- Task-quota cadence: `task-quota-ms` default 0.5 ms (`reactor.cc:4111`), timer
  armed periodic at `3475-3477`. Even under full task load the reactor re-polls at
  least every quota via preemption.

## 2. CPU scheduler — why shares cannot express idle-only

- Hierarchical CFS-style scheduler: `sched_entity` base (`reactor.hh:272`), leaf
  `task_queue` per scheduling group (`reactor.hh:296`), interior `task_queue_group`
  (`reactor.hh:315`, root `_cpu_sched` at `reactor.hh:335`).
- vruntime math: `to_vruntime` scales runtime by `1/shares` (`reactor.cc:1089-1095`);
  lowest vruntime runs next (`indirect_compare`, `1112`). Selection loop:
  `task_queue_group::run_tasks()` (`3333-3365`); leaf execution
  `task_queue::run_tasks()` (`2827-2866`) breaks on
  `internal::scheduler_need_preempt()`.
- **Shares floor is 1.0** (`sched_entity::set_shares`, `reactor.cc:1097-1100`; also
  ctor `1005`). CFS guarantees every active entity ≈ `shares/Σshares` of the CPU —
  a shares=1 group is deprioritized, never idle-gated.
- **The activate clamp makes it worse for idle-only**: on wake,
  `tq->_vruntime = max(_last_vruntime, tq->_vruntime)` (`reactor.cc:3223`), so a
  long-idle low-share queue enters with the *lowest* vruntime among peers and
  typically runs *next*, ahead of busy high-share queues, until it catches up.
- Preemption: `need_preempt()` reads the thread-local `preemption_monitor`
  (`include/seastar/core/preempt.hh:29-72`; debug builds: always true; the
  scheduler's variant fires every 64th call in debug, `preempt.hh:81-97`). Who
  flips it: quota timer (aio: kernel completion ring *is* the monitor,
  `reactor_backend.cc:439-476`; epoll: dedicated timer thread,
  `reactor_backend.cc:770-813`), `add_high_priority_task`, `force_poll`. Reset at
  the top of every `run_some_tasks()` (`reactor.cc:3320`).
- No existing lowest-priority machinery: `_at_destroy_tasks` (queue id 1) is
  shutdown-only, shares 1000, not a template. `add_urgent_task` is the high-priority
  mirror; no low-priority insert exists.

## 3. Cross-shard machinery and memory

- `smp_message_queue` (`include/seastar/core/smp.hh:177-299`, impls in
  `reactor.cc`): full N×N matrix of **SPSC** ring pairs (`_pending`/`_completed`,
  128 deep, batch 16). TX stages into shard-local fifos, bulk-pushes at batch size
  (`move_pending`, `reactor.cc:3794`). Destination turns items into scheduled tasks
  (`smp.cc:52`); responses flow back and the *origin* shard runs `complete()` and
  deletes the item (`process_completions`, `reactor.cc:3910`).
- Known cross-shard sharp edges, stated in-tree: `waiting_task()` across shards
  unimplemented/unsafe (`smp.hh:233-235`); exception may be allocated on another
  cpu (`smp.hh:255`).
- `alien::message_queue` (`include/seastar/core/alien.hh:46-98`): per-shard
  **MPMC-capable** `boost::lockfree::queue<work_item*>` (multi-producer in use,
  single consumer), atomic `_sent`, batch 128 — the in-tree template for
  thread-safe injection. Returns `std::future`, not seastar futures.
- Wake protocol (Dekker, asymmetric): sleeper sets `_sleeping` (relaxed) → 
  `try_systemwide_memory_barrier()` → re-polls, aborting sleep if it raced
  (`smp_pollfn::try_enter_interrupt_mode`, `reactor.cc:3104-3119`). Producer:
  compiler-only `atomic_signal_fence(seq_cst)` then `remote->wakeup()`
  (`lf_queue::maybe_wakeup`, `reactor.cc:3867-3878`); `wakeup()` is a relaxed load
  + eventfd write only if sleeping (`reactor.cc:3168-3179`). The expensive barrier
  runs only on the rare sleep transition (`src/core/systemwide_memory_barrier.cc`,
  membarrier-based).
- Memory: owner shard is encoded in pointer bits (`memory.cc:318`). Cross-shard
  free of **any** allocation is supported: CAS push onto the owner's
  `xcpu_freelist` Treiber stack (`memory.cc:1070-1083`), drained lazily
  (`1085-1097`). Objects with shard-local semantics still need `foreign_ptr`
  discipline (`sharded.hh:933`, rationale `911-931`).
- Patterns that keep shared state near-free when cold: relaxed empty-check before
  anything expensive; `alignas(cache_line_size)` isolation; asymmetric barriers;
  shard-local staging + batched publish; lazy draining.

## 4. Execution contexts — what can migrate between pthreads

- **`seastar::thread` (stackful): cannot migrate.** Compilers may cache
  thread-local *addresses* (of `local_engine`, `g_this_shard_id`, `errno`) in
  registers or on the fiber stack across the suspension point — silent corruption
  on resume elsewhere; un-auditable in user code. Additionally the switch chain is
  thread-local (`g_current_context`/`g_unthreaded_context`, `thread.cc:48-49`;
  setjmp/longjmp default, ucontext+ASAN-annotations variant), and fibers sit in a
  per-shard `_all_threads` list (`thread.cc:297`). Documented core-pinned
  (`thread.hh:45-46`).
- **C++20 coroutines: can migrate.** All live state spills into the heap frame;
  `coroutine_handle::resume()` is pthread-agnostic; each resume segment runs
  entirely on one pthread and reloads TLS through fresh calls. Seastar's stock
  promise types derive from `seastar::task` and capture the current scheduling
  group at frame creation (`task.hh:53`, `coroutine.hh:91`); frames allocate via
  `::malloc` → shard pool (`coroutine.hh:72-86`). A migratable type must therefore
  be a *new* promise type, not a reuse.
- Framework tripwire for cross-shard misuse: `SEASTAR_DEBUG_PROMISE` records the
  shard where a continuation was set and aborts if made ready elsewhere
  (`future.hh:865-877`, `future.cc:108-121`).
- Thread-locals that pin execution: `local_engine` (`reactor.hh:809`),
  `g_this_shard_id` (`shard_id.hh:39`), `current_scheduling_group`
  (`scheduling.hh:476`, rewritten per task batch at `reactor.cc:2831`), allocator
  `cpu_mem`/`local_expected_cpu_id` (`memory.cc:668`, `315`), fiber context chain.
- Compiler caveat: thread-local reads must not be cached across coroutine
  suspension points. Historical LLVM bugs here are long fixed, but seastar never
  exercises the path today (its coroutines never change shards) — worth a
  regression test.

## 5. Prior art in-tree

- **No** work stealing, run-anywhere, or off-reactor compute pool exists.
- Closest relative: `thread_pool` + `syscall_work_queue`
  (`src/core/thread_pool.{hh,cc}`, `src/core/syscall_work_queue.hh`) — one helper
  pthread per shard for blocking syscalls. Same shard-affine-edges shape as the
  design (promise created and fulfilled on the shard; opaque callable runs
  elsewhere); SPSC rings + eventfds + seq_cst-flag wake handshake
  (`thread_pool.hh:73-83`, `thread_pool.cc:61-66`); semaphore backpressure at 128
  in flight (`reactor.cc:3749`). Differences that disqualify it as a compute
  vehicle: kernel-scheduled (competes with reactors for CPU), single-shot callables
  with no yield/migration, one-to-one topology.
- `alien` is the injection prior art (see §3); `smp::submit_to` is the
  cross-shard-call prior art; neither migrates a suspended computation.

## 6. Consequences baked into the design

1. Idle-branch hook, not a scheduling group (§2) — strictly-lower-priority is
   otherwise inexpressible.
2. Dedicated coroutine type, not `seastar::thread`, not stock seastar coroutines
   (§4).
3. Global queue must be MPMC — the one structure seastar doesn't already have (§3);
   guard it with the relaxed-empty-check + cache-line-isolation patterns.
4. Completion marshals home over existing machinery, `thread_pool`-style (§5).
5. Frames may be created/destroyed on different shards — allocator already copes
   (§3).
