# Do Not Merge: DST for seastar

Status: draft
Date: 2026-08-20
Author: Alex Gallego

## 1. Summary

This document proposes a design for adding **deterministic simulation
testing (DST)** support to Seastar. DST, in the style pioneered by
FoundationDB's simulator, runs an application's real logic against a
seeded, fully virtualized notion of time, scheduling, disk, and
network, so that an entire run — including concurrency interleavings,
network faults, and crash/restart behavior — is a pure function of a
single seed. A failing run becomes trivially reproducible: re-run with
the same seed and get the same execution, byte-for-byte.

Seastar's role here is to be the **provider of the deterministic
primitives**, not to bake DST into any particular application's test
suite. Downstream applications built on Seastar — Redpanda foremost
among them — write their own DST scenarios (multi-node protocol
tests, crash-recovery tests, etc.) against the primitives this design
adds. Seastar's own unit tests are a secondary beneficiary, used to
validate the primitives themselves.

## 2. Goals

- Make Seastar's reactor loop, on a single shard in a single process,
  fully deterministic given a seed: the same seed always produces the
  same task interleaving, the same simulated I/O completion order,
  and the same injected faults.
- Provide a simulated disk (`file_impl`) that can model realistic
  crash/power-loss semantics: torn writes, write reordering, and loss
  of unfsynced data across a simulated crash-and-restart cycle, all
  within one OS process.
- Provide a simulated network (`socket_impl`) that can model latency,
  loss, reordering, and partitions, extending an existing in-tree
  pattern rather than inventing a new one.
- Make this opt-in at runtime, with **zero behavior change** to
  existing binaries that don't request it.
- Minimize the footprint of changes to Seastar's core (`reactor.cc`/
  `reactor.hh`). Prefer additive library code and reuse of existing
  extension points over new internal machinery.

## 3. Non-goals (this phase)

- **Multi-shard determinism.** This design covers one shard in one
  process. Deterministic cross-shard messaging is a natural
  follow-on and is deferred to a future design once this foundation
  lands.
- **Multi-node cluster-in-one-process simulation** (the full
  FoundationDB-style model, where an entire cluster runs as
  simulated actors inside one OS process). Also deferred, and will
  build on the single-shard primitives from this design.
- **Trace-recording infrastructure.** Reproduction is seed-based:
  same seed, same Seastar/app version → same execution. We are not
  building a separate event-trace log format for replay. (See §9 for
  the determinism-audit implications of this choice.)
- **CI seed-corpus management** (running many seeds, minimizing a
  failing seed, tracking known-bad seeds over time). This is a
  downstream-application/CI concern, not something Seastar itself
  needs to provide.

## 4. Background: what Seastar already has

A survey of the current codebase turned up more reusable groundwork
than expected, which materially shapes the design toward
minimal-diff:

- **`manual_clock`** (`include/seastar/core/manual_clock.hh`) already
  exists as a virtual, `advance()`-able clock usable anywhere a
  `timer<Clock>` is templated on it. It's used today in several unit
  tests. Two gaps: `advance()` is asynchronous (it broadcasts an
  `invoke_on_all` in the background rather than synchronously
  quiescing and firing timers), and it is not wired into the
  subsystems that matter most for scheduling determinism — the I/O
  fair-queue's token bucket, the CPU stall detector, and
  scheduling-group vruntime accounting are all hardcoded to
  `std::chrono::steady_clock`.
- **Task ordering within one scheduling group is already
  deterministic FIFO.** The only existing source of intentional
  disorder is a debug-only `shuffle()` helper in `reactor.cc`, gated
  by `SEASTAR_SHUFFLE_TASK_QUEUE` and seeded from
  `std::random_device` — i.e., deliberately *not* reproducible today,
  and disconnected from the test framework's existing
  `--random-seed` plumbing.
- **Cross-scheduling-group ordering is not deterministic.** Which
  runnable scheduling group goes next is decided by vruntime
  accounting driven by measured wall-clock task runtime, and
  task-quota preemption is driven by a real POSIX timer/signal. This
  is the single biggest real-time dependency standing between
  Seastar's current scheduler and full determinism.
- **`file_impl` and `socket_impl`/`connected_socket` are already
  pluggable at the object level.** `file` has a public constructor
  taking any `shared_ptr<file_impl>`, and Seastar's own test suite
  (`tests/unit/loopback_socket.hh`) already builds a complete
  in-memory, in-process network backend — including a rudimentary
  fault-injection interface (`loopback_error_injector`) — by
  constructing `connected_socket`/`server_socket` directly from
  custom impls. Neither of these required touching reactor internals
  or the hardcoded `network_stack` registration list.
- **`alloc_failure_injector`** (`include/seastar/util/alloc_failure_injector.hh`)
  is an existing, deterministic, *counter-based* (not random-sampled)
  fault-injection mechanism used throughout the test suite. Its
  design — "fail the Nth occurrence," not "fail with probability p"
  — is the right pattern to generalize for disk and network fault
  injection, since counter-based injection composes cleanly with a
  seed (the seed picks which N).

The upshot: the object-construction-level extension points for disk
and network are already sufficient for a simulated backend to bypass
reactor internals entirely. The one place minimal-but-real core
changes are unavoidable is clock/scheduler determinism.

## 5. Architecture overview

Simulation mode is a new value for Seastar's existing reactor-backend
selection mechanism: `--reactor-backend=simulation
--simulation-seed=<N>`. This follows the same shape applications
already use to pick `epoll` / `linux-aio` / `io_uring`, so opting in
is a startup-flag change, not a code or build change, for the
application.

A single seed is the only source of randomness for an entire run. It
is expanded into purpose-scoped sub-streams (scheduler shuffle, disk
fault injection, network fault injection, latency distributions) by
hashing the seed together with a purpose tag, the same technique the
existing test runner already uses to derive per-shard seeds
(`seed + this_shard_id()`) for `local_random_engine`. Keeping each
consumer on its own derived stream avoids one component's RNG
consumption accidentally perturbing another's — an easy way to lose
reproducibility across an unrelated code change.

Four building blocks compose the design:

1. **Deterministic clock** — an extended `manual_clock`.
2. **Deterministic scheduler** — templated clock sources plus a
   seeded shuffle and step-driven preemption.
3. **Simulated disk** — a new `file_impl`.
4. **Simulated network** — a generalized `loopback_socket.hh`.

A fifth piece, the **simulation driver**, is the one substantially
new component: it owns the seed, constructs the clock and RNG
sub-streams, wires the simulated file/socket factories into the
application under test, and drives the run loop.

## 6. Clock virtualization

`manual_clock::advance()` today only *schedules* timer expiry as a
background cross-shard broadcast; it does not synchronously drain
runnable work first. For a simulation driver that needs to advance
time only when the reactor has genuinely gone idle — otherwise a
timer could fire "early" relative to still-pending immediate work —
this is insufficient as-is. The design adds a new, purely additive
method (a quiesce-and-advance primitve) that only moves the clock
forward once no task is runnable, then synchronously drains due
timers before returning control to the driver loop. This does not
change the behavior of `manual_clock::advance()` for existing
call sites; it is a new entry point layered on top.

Separately, three call sites identified in the survey are hardcoded
to `std::chrono::steady_clock` and need to become clock-templated:

- The I/O fair-queue's token bucket (`io_queue`/`fair_queue`),
  which already has a sibling utility, `shared_token_bucket`, that is
  *already* templated on `Clock` and *already* tested against
  `manual_clock` elsewhere in the test suite. Templating the
  fair-queue's own token bucket the same way is a small, precedented
  change.
- The CPU stall detector's timer source.
- Scheduling-group vruntime accounting (`sched_clock` in
  `reactor.hh`).

In all three cases the template parameter defaults to
`std::chrono::steady_clock`, so unmodified production builds are
byte-identical in behavior. Only when the simulation backend is
selected are these instantiated against the virtual clock.

## 7. Deterministic scheduling

Two changes make scheduling itself a pure function of the seed:

- **Seed the existing shuffle.** The task-shuffle helper already
  exists and already does exactly what a DST harness wants — perturb
  task queue order to shake out ordering-dependent bugs — but is
  seeded from `std::random_device` and gated to debug/sanitizer/fuzz
  builds only. This design connects it to the simulation seed's
  scheduler sub-stream and activates it whenever the simulation
  backend is selected, independent of build type. Behavior for
  non-simulation builds and for simulation-mode-off runs is
  unchanged.
- **Replace wall-clock-driven preemption with a deterministic
  trigger.** Task-quota preemption currently fires from a real POSIX
  timer/signal, and vruntime accounting is derived from measured
  elapsed wall-clock time per task quantum. Under the simulation
  backend, this design substitutes a deterministic trigger — a fixed
  logical step or virtual-time budget per quantum, driven by the
  same virtual clock from §6 — so that *which* scheduling group runs
  next, and *when* a running task gets preempted, depends only on
  program logic and the seed. The real-mode POSIX-timer path is
  untouched; this substitution only takes effect under the
  simulation backend.

Together with the already-deterministic FIFO ordering within a
single scheduling group, this closes the gap needed to reproduce
concurrency bugs that manifest across multiple scheduling groups —
directly relevant to applications like Redpanda that use separate
scheduling groups for e.g. compaction versus user-request traffic.

## 8. Simulated disk

A new `simulated_file_impl` is added as an implementation of the
existing `file_impl` interface, requiring no changes to
`reactor.cc`, `io_queue`, or the I/O-sink/reactor-backend layer:
`file`'s public constructor already accepts any
`shared_ptr<file_impl>`, so simulated files are handed to application
code the same way `mock_read_only_file` and `layered_file_impl`
already demonstrate in the existing test suite.

The simulated file distinguishes **durable** writes (those that have
completed an fsync/flush boundary) from **uncommitted** writes (those
that have not). A deterministic, counter-based fault injector — using
the same "fail on the Nth occurrence" pattern as
`alloc_failure_injector` rather than probabilistic sampling — can
mark an in-flight write as torn (partially applied), reordered
relative to a concurrent write to overlapping ranges, or entirely
lost. Latency for each operation is injected via a seeded
distribution, scheduled against the virtual clock from §6 so it costs
no real wall-clock time.

A `simulate_crash()` operation on the driver (§10) models a
power-loss event: it discards all uncommitted writes, applies
whatever torn-write corruption was scripted for writes that were
in-flight at the moment of the crash, and then hands back a freshly
constructed application instance that reopens the same simulated
disk — a full logical restart without leaving the OS process. This
directly targets crash/recovery correctness bugs (e.g., a missing
fsync before an on-disk pointer update becomes durable) that are very
difficult to hit reliably with real crash-and-restart testing.

## 9. Simulated network

`tests/unit/loopback_socket.hh` already demonstrates the right shape
for this: a complete in-memory `socket_impl`, `connected_socket_impl`,
and `server_socket_impl` implementation that several existing tests
(RPC, TLS, connect, unix-domain-socket tests) already build on, along
with a basic error/delay injection interface. It bypasses Seastar's
`network_stack` registration mechanism entirely by constructing
sockets directly from custom impls — the same reason this is the
lower-risk path for disk, above.

This design generalizes that existing test-only header into a public
component, and extends its fault-injection interface with:

- Seeded latency distributions (replacing the current injector's
  real `sleep()`-based delay with one scheduled against the virtual
  clock).
- Packet loss and message reordering.
- Partition modeling: dropping all traffic between a given pair of
  simulated endpoints for a scripted duration.

No changes to `network_stack`'s hardcoded registration list, or to
any reactor-internal networking code, are required.

## 10. The simulation driver

The simulation driver is the one component that is substantially new
rather than a generalization of something already in-tree. It:

- Owns the seed and derives the sub-streams described in §5.
- Constructs the virtual clock and instantiates the templated
  fair-queue/stall-detector/vruntime clock sources against it (§6).
- Constructs the simulated file and socket factories (§8, §9) and
  wires them into the application under test's dependency-injection
  points (however the application obtains its `file`/
  `connected_socket` objects today).
- Drives the run loop: let the reactor run until quiescent, advance
  the virtual clock via the new quiesce-and-advance primitive (§6),
  inject any faults scheduled to occur at that point, and repeat.
- Exposes `simulate_crash()` (§8) for crash-recovery scenarios.

This lives as a distinct, optional module — proposed as
`seastar::testing::simulation` — rather than being folded into
`seastar::testing` generally, since it is meant to be a public API
surface that downstream applications write scenario code against,
not an internal detail of Seastar's own test suite.

## 11. Opt-in and compatibility

Selecting simulation mode is a single new entry in the existing
reactor-backend selector, plus a seed flag
(`--reactor-backend=simulation --simulation-seed=<N>`), following the
same shape as the existing `epoll`/`linux-aio`/`io_uring` backend
selection. Every other change described in this document is either:

- Purely additive (the quiesce-and-advance clock method, the
  simulated `file_impl`/`socket_impl`, the simulation driver module),
  or
- Default-templated to preserve existing behavior exactly (the three
  clock-templated call sites in §6), or
- Gated behind the simulation backend at runtime (the seeded shuffle
  and deterministic-preemption substitution in §7).

An application that never passes `--reactor-backend=simulation` sees
no behavior change and no new build-time cost beyond the (already
precedented) cost of a few additional template instantiations.

## 12. Testing the simulation harness itself

Before downstream applications build on this, Seastar's own test
suite gets:

- A toy application exercising file and network I/O under the
  simulation driver, run across a range of seeds with an oracle
  check on final state — validates that the harness behaves
  correctly, not just that it runs.
- A same-seed-twice determinism self-check: run the same scenario
  twice with the same seed and assert that the sequence of scheduled
  task identifiers and clock advances is identical between the two
  runs. This is a cheap, permanent regression check that determinism
  actually holds, without requiring the trace-recording
  infrastructure explicitly excluded in §3.

## 13. Risks and open questions

- **Residual non-determinism sources.** Anything that leaks
  observable behavior from hash-table iteration order, pointer-value
  tie-breaking, or similarly ASLR-sensitive state would silently
  break reproducibility even after this design lands. This needs an
  explicit audit pass over the code paths exercised by simulation
  mode, and ongoing vigilance (e.g. review-time awareness) rather
  than a one-time fix — it is not something a single change closes
  off permanently.
- **Non-determinism from outside Seastar's control.** A dependency
  that calls `gettimeofday`, `getrandom`, or similar directly, rather
  than going through Seastar's clock/RNG abstractions, will
  reintroduce real-world non-determinism that this design cannot
  detect or prevent. This is called out here explicitly as a
  responsibility boundary: it falls to the application author to
  ensure their own code and dependencies route time and randomness
  through Seastar's (now virtualizable) primitives.
- **Scope creep risk on the scheduler change.** §7 is the most
  invasive part of this design because it touches `reactor.cc`
  preemption logic directly, rather than being purely additive like
  the disk/network pieces. It should be implemented and reviewed as
  its own, isolated change, separate from the additive disk/network/
  driver work, so it can be evaluated on its own merits and rolled
  back independently if it proves too risky.

## 14. Phasing

- **Phase 1 (this document):** single shard, single process,
  clock/scheduler determinism, simulated disk and network, and the
  simulation driver as described above.
- **Phase 2 (future document):** multi-shard determinism within one
  process, including deterministic ordering of cross-shard messages.
- **Phase 3 (future document):** multi-node, cluster-in-one-process
  simulation in the FoundationDB style, built on the Phase 1 and
  Phase 2 primitives.
