# dmabench design and implementation handoff

## Task and scope

Implement a standalone, driver-agnostic DMAengine memcpy benchmark, consisting
of a kernel test module and a userspace command. This document is the design
and implementation instruction for the implementing agent.

The user will test on hardware manually. Only build validation is required:
do not load the module, run DMA traffic, install the tool or kernel, or invent
a hardware test environment. Use the existing kernel output directory
`.build/dmabench`, which the user has already configured. Preserve its
configuration except for enabling the new benchmark option as necessary.

Do not change DMAengine providers, including SDXI. Do not adapt the design to
the current implementation of any particular provider. Exclude channels with
`DMA_COMPLETION_NO_ORDER`; unordered completion is deliberately unsupported.
Individual transfer error aggregation is not a priority for this version.
Basic validation, timeout handling, and safe resource lifetime are required.

Inspect the current working-copy change with `jj status` and `jj diff` before
editing. Preserve existing user changes. Use `apply_patch` for source edits.
Do not rewrite existing history or publish anything. Follow applicable
AGENTS.md instructions; SDXI-specific guidance applies if the work expands
into SDXI development, which this task does not require.

## Deliverables

- `drivers/dma/dmabench.c`, with Kconfig and Makefile integration.
- `include/uapi/linux/dmabench.h`, shared by kernel and userspace.
- `tools/dma/dmabench.c`, with build integration in `tools/dma/Makefile`.
- User documentation in `Documentation/driver-api/dmaengine/`, linked from
  that directory's documentation index.
- A handoff stating the exact build commands and results, with limitations
  of the benchmark clearly documented.

Keep this planning document separate from the installed user documentation.
Do not implement unrelated modes or add automated runtime tests. Review code
and build it; the user will perform runtime validation.

## What the benchmark measures

Measure sustained payload throughput through the DMAengine client API with:

- buffers allocated and DMA mapped before timing;
- an independently controlled maximum outstanding transaction count;
- several memcpy submissions per `dma_async_issue_pending()` call;
- interrupt requests and callbacks only at submission batch boundaries;
- rotation through a pool larger than the outstanding queue if requested;
- CPU initialization and verification outside the timed interval.

The timed interval includes descriptor preparation, submission, issuing work,
completion notification, worker scheduling, initial queue fill, and final
drain. Subtract nothing. This is DMAengine client throughput, not an isolated
measurement of hardware execution time. No descriptor reuse is assumed.

For memcpy, payload bytes are bytes copied, not reads plus writes. Copying N
bytes generally entails N bytes of reads and N bytes of writes. Report that
distinction in documentation. Large working sets and large individual copies
are separate controls and have different allocation constraints.

## Interface: one synchronous ioctl on debugfs

Create `/sys/kernel/debug/dmabench` with mode `0600`. Module initialization
creates the endpoint and starts no benchmark. Use `CONFIG_DMABENCH` as a
tristate depending on DMAengine and debugfs, positioned alongside dmatest.
No module parameters, separate configuration files, global run trigger, or
global result file are needed.

Provide one `DMABENCH_RUN` ioctl. One call supplies the complete configuration,
performs allocation, warmup, measurement, drain, and optional verification,
then returns results. Calls on the same open file must not share mutable run
configuration. Prefer request-local state; each call reserves its channel
exclusively with DMAengine. Independent channels may be benchmarked concurrently.
Reject a missing or busy requested channel with a documented errno. Do not
silently benchmark a different channel or fall back to CPU copying.

The DMA mapping benchmark is interface precedent, not code to copy wholesale:
`kernel/dma/map_benchmark.c`, `include/uapi/linux/map_benchmark.h`, and
`tools/dma/dma_map_benchmark.c`. In particular, do not copy its shared mutable
request state or bind dmabench as a replacement PCI/platform driver. dmabench
is a DMAengine client of an already registered provider.

Use a fixed-size ioctl structure with configuration and result substructures.
Use `__u32`, `__s32`, and `__aligned_u64` where appropriate; explicit layout
must be identical for native and compat callers. No pointers, `long`, `size_t`,
or C enums in the ABI. A fixed-length channel string is sufficient. Include
`<linux/ioctl.h>` in the UAPI header. Check the ioctl-number registry before
choosing an encoding; do not collide with DMA_MAP_BENCHMARK.

Include zero-required reserved fields for modest future extension; reject
unknown flags and nonzero reserved input. Zero output fields in the kernel
before use and never expose padding or uninitialized memory. Set
`.owner = THIS_MODULE` and provide compat ioctl handling for the identical
layout. A fixed ABI does not need speculative extensible pointer arrays or
an elaborate version negotiation protocol.

### Configuration

| Field | Meaning |
| --- | --- |
| channel | Exact DMA channel name, e.g. `dma0chan0`; required |
| transfer_size | Payload bytes per memcpy transaction |
| queue_depth | Maximum submitted copies not yet reclaimed through a batch completion |
| batch_size | Maximum submissions before issue_pending; notification on last copy |
| buffer_count | Number of distinct source/destination pairs |
| transfers | Number of copies in measured phase |
| warmup_transfers | Number of copies before measured phase; zero permitted |
| cpu | Worker CPU, or -1 for unbound |
| timeout_ms | Maximum interval without batch completion progress |
| flags | Initially optional data verification only |

Require `1 <= batch_size <= queue_depth <= buffer_count`, nonzero transfer
count and size, and a positive timeout. Reject malformed or unterminated
channel names. Validate CPU selection, provider copy alignment, conversion
to `size_t`, page rounding, allocation size and count products, and payload
counter overflow. Establish documented resource limits so arbitrary input
cannot cause unbounded metadata allocation or nonsensical waits. Fail clearly
on unsupported lengths rather than changing the requested transfer size.

CLI defaults, proposed: 64 KiB per copy, queue depth 64, batch size 16,
buffer count 1024, 100000 measured copies, 4096 warmup copies, 3000 ms progress
timeout, unbound worker, and verification disabled. The channel has no default.
Defaults belong in userspace; the kernel validates explicit requests.

Defer strict buffer NUMA-node selection: `dma_alloc_noncontiguous()` has no
explicit node argument. CPU selection controls the worker only and must not
be documented as a guarantee of buffer locality. Do not change device-global
NUMA state or DMA masks to implement placement. Also defer user buffers,
multi-channel requests, descriptor reuse, duration-based runs, hardware
polling modes, and interrupt moderation controls.

### Results and userspace command

Return raw integer results: elapsed nanoseconds, measured submitted and
completed copies, completed payload bytes, measured issue_pending calls,
and actual allocation bytes. Retain the effective input configuration.
Optionally include inexpensive additional counters if they have precise
semantics, but worker CPU time, depth histograms, and latency distributions
are not requirements for the first version. Avoid instrumenting every copy
with timestamps just to report supplementary statistics.

The CLI computes MiB/s, GiB/s, and transactions/s from returned bytes/counts
and elapsed time. Offer long options matching the configuration fields and
`--json` for scripting. Validate numeric input with checked conversion, not
`atoi()`. Print configuration with results. Clearly report ioctl errors;
do not print a failed run as a valid performance result. A single command
should suffice, for example:

```sh
sudo tools/dma/dmabench --channel dma0chan0 --transfer-size 65536 \
    --queue-depth 64 --batch-size 16 --buffer-count 1024 \
    --transfers 100000 --warmup-transfers 4096
```

Support repeated calls without reloading the module. No asynchronous job API
is needed. A signal should stop new submissions, quiesce DMA and callbacks,
and return an interruption error. Do not transparently restart an interrupted
benchmark. Partial-result retrieval on error is deferred.

## Buffers: kernel allocations, non-coherent DMA ownership

Allocate each source and destination independently with
`dma_alloc_noncontiguous()` on `dmaengine_get_dma_device(chan)`. Use
`DMA_TO_DEVICE` for sources and `DMA_FROM_DEVICE` for destinations. This API
already returns mapped memory and guarantees one DMA segment, despite
possibly multiple physical segments. Do not call dma_map_sg again on it.
Obtain the transaction addresses with `sg_dma_address()` from the returned
table and confirm that the mapped segment covers the requested range.

Use page-rounded allocation sizes and report their actual sum over sources
and destinations. The memcpy length remains the exact requested payload
length. Respect the device's DMA allocation/mapping limits and provider
alignment. A large total pool does not require one large allocation. With
an IOMMU, a large individual allocation may be backed by scattered pages;
without one the allocator can require contiguous physical memory and fail.
Do not silently divide one requested memcpy into multiple transactions.

These are non-coherent streaming-style allocations, not coherent buffers.
Initialize every source with deterministic data and every destination with
a different pattern even when verification is disabled. Do not benchmark
uninitialized source data. Unique patterns per pair improve verification.

For CPU access use `dma_vmap_noncontiguous()` and its matching vunmap API,
or a carefully justified page-based alternative. If using vmap, follow both
cache-alias and DMA ownership requirements:

1. Initialize buffers through the CPU mapping.
2. Flush the CPU vmap ranges after CPU writes, then synchronize the sg tables
   for the device before handing the buffers to DMA.
3. Keep buffers device-owned throughout warmup and measurement. Sources are
   immutable; the CPU never reads or writes either pool in those phases.
   Repeated device accesses need no per-copy CPU/device ownership transitions.
4. After DMA has drained, synchronize tables for the CPU and invalidate vmap
   aliases before reading device-written data for verification.
5. Vunmap and free using the matching device, allocation size, direction,
   and sg table, only after DMA and callbacks are quiescent.

No two outstanding transactions may write the same destination. Rotate through
all `buffer_count` pairs in order rather than repeatedly using only the first
`queue_depth`. Reuse a pair only after the batch containing its previous copy
has completed. Sequential submission and reclamation with buffer_count at
least queue_depth make this straightforward.

Optional verification is outside timing. A complete untimed pass through the
pool may validate every pair before warmup; re-poison destinations and hand
them back to DMA afterward. After measurement, verify pairs known to have
been copied; do not report untouched pairs as failures when the requested
run is shorter than the pool. Document that final contents cannot prove every
repeated identical copy executed correctly. This is not a replacement for
dmatest's correctness coverage.

## Batching and completion contract

Reserve one channel with DMA_MEMCPY capability and reject
DMA_COMPLETION_NO_ORDER. Prepare and submit each descriptor in adjacent steps:
some providers retain a lock between prep and submit, so do not prepare an
array first and submit it later.

For ordinary copies use DMA_CTRL_ACK. For the last copy in each submission
batch also set DMA_PREP_INTERRUPT and attach a callback (callback_result is
acceptable, but aggregate per-copy errors are out of scope). Earlier copies
have no callback and no interrupt request. Call dma_async_issue_pending after
each batch, including partial batches and the final batch of each phase.
Do not set DMA_PREP_FENCE on every independent copy.

DMA_PREP_INTERRUPT requests notification of that transaction; it is not a
serialization or dependency flag. Ordered channel completion provides the
boundary: notification that the final copy has completed implies completion
of copies submitted before it. The provider/hardware may execute independent
copies concurrently or out of order internally while presenting ordered
completion to the client. This does not establish success of every earlier
copy and does not imply CPU ownership of streaming buffers.

Do not rely on callbacks for descriptors without DMA_PREP_INTERRUPT, on
callbacks preceding the boundary having run, or on one wakeup per interrupt.
No earlier callbacks are installed in this design. Do not require
DMA_INTERRUPT capability or a separate interrupt-only descriptor: the last
memcpy supplies the boundary notification.

Use one submitting kthread per request and bounded, preallocated batch
records. Each record carries a terminal submitted sequence and batch length.
Initialize all callback-visible state before submitting the terminal copy.
Completion may race submission or arrive before issue_pending returns.
Publish progress with a lock or correct release/acquire synchronization.
Keep callback work minimal and non-sleeping; no allocations, submissions,
verification, or channel termination from callbacks.

Prefer marking individual batch records complete and reclaiming completed
records from the head. This avoids depending on callback execution order to
update a global watermark. Callback publication must be its final access to
a record that the worker can recycle; otherwise provide an explicit lifetime
mechanism. Handle record wraparound without confusing an old completion with
a new use. Never recycle descriptors owned by the provider.

Fill up to queue_depth, issue after at most batch_size submissions, consume
available completed batches, and replenish free capacity. Several batches
may remain outstanding. Do not wait for all outstanding work to drain between
batches. Issue a partial batch when queue space or remaining transfer count
requires it; do not wait for a full batch and accidentally stall the channel.
Consume all available completion progress when awakened.

## Phases, timing, and teardown

The lifecycle is reserve, allocate/initialize, optional correctness pass,
warmup, warmup drain, measured run, measured drain, quiesce, optional final
verification, free, release. Warmup uses the same submission machinery and
buffers. Start a fresh measured accounting epoch only after it has drained.

Start ktime_get_ns immediately before preparing the first measured copy.
Record the terminal completion timestamp in the final measured batch's
callback before publishing it. Stop timing at that timestamp, excluding
later worker wakeup and cleanup. Elapsed time still includes callback
delivery latency. Keep warmup and verification counters out of measured
results. Report zero or otherwise invalid elapsed time as an error.

Use interruptible worker waits plus a progress timeout. Because the ioctl
thread waits for its worker, interruption must request cancellation and wake
the worker even if it is blocked waiting for completions. Do not use
kthread_stop as a substitute for hardware synchronization. Refresh the
progress deadline on completed batches, not on new submissions. Check
cancellation during submission loops as well as waits.

On any exit after submission, stop further issuing, then terminate and
synchronize in sleepable context before freeing DMA memory or callback state.
Use dmaengine_terminate_sync, honor its return value, and require the provider
operations needed for safe cancellation before starting the run. Successful
termination is relied on according to the DMAengine contract; no
provider-specific workarounds are in scope. If termination fails while work
may remain active, never continue into ordinary unmap/free/release: preserve
the live resources and report the failure. Design that exceptional lifetime
path explicitly rather than hiding it behind a cleanup label; leaking or
retaining resources is preferable to DMA use-after-free. Document any resulting
unload restriction. Normal complete runs must not leak resources.

Quiesce callbacks on normal completion too before releasing their storage.
Module/file lifetime must prevent unload while callbacks or workers can still
reference module code. Account for debugfs removal and concurrent ioctls.
Check every preparation/submission/allocation failure, including a partially
submitted batch lacking its planned terminal callback; termination is needed
there. Basic safe failures are required even though detailed DMA error
aggregation is deferred.

## Supporting material to consult

- `include/linux/dmaengine.h`: flag definitions, memcpy prep, DMA device
  selection, issue_pending, cookie status, and termination contracts.
- `Documentation/driver-api/dmaengine/provider.rst`: ordered completion and
  DMA_COMPLETION_NO_ORDER; provider submission/issue responsibilities.
- `drivers/dma/dmaengine.h`: completed-cookie boundary implementation.
- `Documentation/core-api/dma-api.rst`: dma_alloc_noncontiguous, DMA sync,
  vmap alias maintenance, and matching release operations.
- `kernel/dma/mapping.c`: IOMMU allocation versus contiguous fallback.
- `Documentation/filesystems/debugfs.rst` and
  `Documentation/driver-api/ioctl.rst`: endpoint and ioctl conventions.
- `kernel/dma/map_benchmark.c` and `tools/dma/`: benchmark interface/build
  precedent. No changes to the mapping benchmark's behavior are needed.

## Implementation sequence and build-only acceptance

1. Inspect the worktree, build configuration, and current APIs. Implement the
   UAPI, kernel module, CLI, build integration, and user documentation as a
   focused change. Resolve routine implementation details locally while
   preserving the decisions in this document.
2. Enable CONFIG_DMABENCH in `.build/dmabench/.config` if needed, preferably
   as a module when CONFIG_MODULES permits. Preserve the user's other settings.
   For example, use scripts/config with --file and --module DMABENCH, then
   `make O=.build/dmabench olddefconfig`. Check the effective option afterward.
3. Build using `make O=.build/dmabench -j<N>`. If configured as a module,
   ensure the module is compiled and linked through the normal module build,
   including modpost; a successful compilation of dmabench.o alone is not
   sufficient. Choose a reasonable N for available resources.
4. Build the userspace tool with the updated tools/dma build rules. Keep
   generated artifacts under `.build/dmabench` where the rules support an
   output directory, e.g. an explicitly created tools subdirectory. Verify
   those rules actually build the new tool, not just the existing benchmark.
5. Review ABI layout, all lifetime/error paths, callback publication, queue
   wraparound, cache ownership, and integer arithmetic. Run diff/checkpatch
   checks appropriate to new kernel code. Fix build warnings introduced by
   the change. Do not require runtime tests, KUnit, or SDXI-specific builds.
6. Finish with paths to the implementation and documentation, actual build
   commands and results, effective CONFIG_DMABENCH setting, and the manual CLI
   invocation. State explicitly that hardware behavior is untested.

If a build depends on unavailable tools or dependencies, report the concrete
failure and what was successfully built. Do not replace the configured output
directory with a fresh configuration or claim runtime validation.
