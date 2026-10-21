# dmabench design and implementation handoff

## Task and scope

Implement a standalone, driver-agnostic DMAengine memcpy benchmark, consisting
of a kernel test module and a userspace command. This document is the design
and implementation instruction for the implementing agent.

The user will test on hardware manually. Only build validation is required:
do not load the module, run DMA traffic, install the tool or kernel, or invent
a hardware test environment. Use the existing kernel output directory
`.build/dmabench`, which the user has already configured. Preserve its
configuration, including `CONFIG_DMABENCH=m`.

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
| transfer_order | Copy exactly `PAGE_SIZE * 2^transfer_order` payload bytes |
| queue_depth | Maximum submitted copies not yet reclaimed through a batch completion |
| batch_size | Maximum submissions before issue_pending; notification on last copy |
| buffer_count | Number of distinct source/destination pairs |
| transfers | Number of copies in measured phase |
| warmup_transfers | Number of copies before measured phase; zero permitted |
| timeout_ms | Maximum interval without batch completion progress |
| flags | Initially optional data verification only |

Require `1 <= batch_size <= queue_depth <= buffer_count`, nonzero transfer
count, a nonnegative transfer order, and a positive timeout. Reject malformed
or unterminated channel names. Validate provider copy alignment,
conversion to `size_t`, allocation size and count products, and payload
counter overflow. Establish documented resource limits so arbitrary input
cannot cause unbounded metadata allocation or nonsensical waits. Fail clearly
on unsupported lengths rather than changing the requested transfer size.
Validate the order before shifting. Derive the effective byte length once in
request-local state and use it for alignment, allocation, initialization,
submission, verification, and payload accounting. Allocation and payload
lengths are identical; never round or split a requested copy. Retain the 1 GiB
per-copy and 16 GiB total source/destination pool limits, the 4096 queue-depth
and 65536 buffer-pair limits, and the 600000 ms timeout limit. Check metadata
products, `size_t` representability, and measured/warmup payload overflow.

CLI defaults: transfer order 0 (one kernel page), queue depth 64, batch size 16,
buffer count 1024, 100000 measured copies, 4096 warmup copies, 3000 ms progress
timeout, and verification disabled. The channel has no default.
Defaults belong in userspace; the kernel validates explicit requests. The same
order means different byte sizes on kernels with different page sizes.
Maximum permitted order is 18 with 4 KiB pages or 14 with 64 KiB pages, each
giving a 1 GiB copy and permitting at most eight pairs under the pool limit.
Order describes copy size, not physical contiguity; do not limit it to the
buddy allocator's maximum order.

Require all source/destination backing pages to reside on the allocation
device's NUMA node. Capture `dev_to_node()` after channel reservation using
`dmaengine_get_dma_device(chan)`. Fall back to `first_online_node` when
`dev_to_node()` returns `NUMA_NO_NODE`. Require a valid online node with memory,
returning `-EOPNOTSUPP` with a clear diagnostic otherwise; use node 0 without
NUMA. Allocate with `__GFP_THISNODE` and verify every backing page immediately
after allocation using the CPU-side sg-table page iterator, before vmap or
initialization. Require every `page_to_nid()` to match the captured node;
return `-EXDEV` with a diagnostic on mismatch, cleaning up all allocations
without retry. Retain verification because CMA and allocation pools may not
honor the flag. The guarantee covers every page in every source/destination
allocation but excludes metadata and provider-owned descriptors.

After input validation, the ioctl reserves the channel, holds the allocation
device reference, and validates its node before creating the worker. Initialize
request synchronization before startup. Use
`kthread_create_on_node(dmabench_worker, req, req->buffer_node, "dmabench/%s",
req->run.config.channel)` and wake the worker without explicit CPU binding or
custom affinity. In this kernel, first wakeup applies affinity to housekeeping
CPUs on the reported `buffer_node`. Accept fallback to other housekeeping CPUs
when no local eligible CPUs are available, including after CPU hotplug; this
is preferred locality, not a strict worker placement guarantee. It does not
control interrupt affinity or guarantee provider descriptor locality. There
is no CPU field or `--cpu` option. Before startup, all failures, including a
partially failed reservation or interrupted worker creation, must release any
acquired channel and device reference exactly once. Once woken, the worker owns
resource cleanup and exceptional retention; the ioctl must not clean them up
again. Add no user-selectable placement option and change no device-global
NUMA state, DMA masks, or provider policies. Defer user buffers,
multi-channel requests, descriptor reuse, duration-based runs, hardware
polling modes, and interrupt moderation controls.

### Results and userspace command

Return raw integer results: elapsed nanoseconds, measured submitted and
completed copies, completed payload bytes, measured issue_pending calls,
exact allocation bytes, effective `transfer_size` in bytes, and signed
`buffer_node`. Retain the effective input configuration. Use a 96-byte config
with `__u32 transfer_order`, a 96-byte result, and a 192-byte run structure,
all aligned to 8 bytes with no implicit padding. The unpublished ioctl ABI
may change; do not preserve the old layout or command encoding. Compile the
native and compat ABI checks against the new sizes, offsets, and encoding.
Optionally include inexpensive additional counters if they have precise
semantics, but worker CPU time, depth histograms, and latency distributions
are not requirements for the first version. Avoid instrumenting every copy
with timestamps just to report supplementary statistics.

The CLI computes MiB/s, GiB/s, and transactions/s from returned bytes/counts
and elapsed time. Offer long options matching the configuration fields and
`--json` for scripting. Print requested order, effective bytes, and buffer node
in both text and JSON. Validate numeric input with checked conversion, not
`atoi()`. Print configuration with results. Clearly report ioctl errors;
do not print a failed run as a valid performance result. A single command
should suffice, for example:

```sh
sudo .build/dmabench/tools/dma/dmabench --channel dma0chan0 --transfer-order 0 \
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
`DMA_TO_DEVICE` for sources and `DMA_BIDIRECTIONAL` for CPU-poisoned destinations,
consistently through allocation, synchronization, and free. This API
already returns mapped memory and guarantees one DMA segment, despite
possibly multiple physical segments. Do not call dma_map_sg again on it.
Obtain the transaction addresses with `sg_dma_address()` from the returned
table and confirm that the mapped segment covers the requested range.

Use the exact page-order-derived length for allocation and memcpy, and report
its sum over sources and destinations (`2 * buffer_count * transfer_size`).
Respect the device's DMA allocation/mapping limits and provider
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

The lifecycle is reserve, validate node, create/wake worker, allocate/initialize,
optional correctness pass,
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

At the beginning of each nonempty phase reset a request-local timeout latch
and initialize progress under the existing callback/publication spinlock.
Each batch callback captures current jiffies under that lock and compares it
with the previous progress deadline, using `msecs_to_jiffies()` and wrap-safe
`time_after_eq()`, before refreshing progress. Latch expiry for completion at
or after the deadline; never clear it within a phase. The worker checks the
latch under the same lock before accepting any completion, including final
completion and phase success. Return `-ETIMEDOUT` through normal synchronous
termination and cleanup without successful performance results. Detect at
batch boundaries only: add no per-transfer deadline checks or timestamps,
watchdog, or timeout options. A late completion can reveal expiry after the
fact. An executing provider operation cannot be interrupted; the timeout does
not bound allocation, verification, or provider termination time. Keep prep
and submit adjacent and retain resources/module pinning if termination fails.

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
2. Preserve `.build/dmabench/.config`, including `CONFIG_DMABENCH=m`, and check
   the effective option after building.
3. Build using `make O=.build/dmabench -j16`. If configured as a module,
   ensure the module is compiled and linked through the normal module build,
   including modpost; a successful compilation of dmabench.o alone is not
   sufficient.
4. Build the userspace tool with the updated tools/dma build rules. Keep
   generated artifacts under `.build/dmabench` where the rules support an
   output directory, e.g. an explicitly created tools subdirectory. Verify
   those rules actually build the new tool, not just the existing benchmark.
5. Update and compile the existing 32-bit and 64-bit ABI checks for matching
   sizes, every offset, alignment, and ioctl encoding. Review order 0, maximum
   order, excessive orders before shifting, pool/payload overflow, alignment
   rejection, unusable nodes, mixed-node and partial allocations, cancellation,
   termination failure, late final completion, warmup isolation, and jiffies
   wraparound. Review all lifetime/error paths, callback publication, queue
   wraparound, cache ownership, and integer arithmetic. Run diff/checkpatch
   checks appropriate to new kernel code. Fix build warnings introduced by
   the change. Do not require runtime tests, KUnit, or SDXI-specific builds.
6. Finish with paths to the implementation and documentation, actual build
   commands and results, effective CONFIG_DMABENCH setting, and the manual CLI
   invocation. State explicitly that hardware behavior is untested.

If a build depends on unavailable tools or dependencies, report the concrete
failure and what was successfully built. Do not replace the configured output
directory with a fresh configuration or claim runtime validation.
