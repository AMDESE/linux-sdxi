.. SPDX-License-Identifier: GPL-2.0

DMAengine memcpy benchmark
=========================

dmabench measures sustained payload throughput through the DMAengine client
API. It consists of the ``CONFIG_DMABENCH`` kernel module, a synchronous
``DMABENCH_RUN`` ioctl on ``/sys/kernel/debug/dmabench`` (mode 0600), and the
``tools/dma/dmabench`` command. Loading the module creates the endpoint without
starting transfers. The DMA provider must already be registered.

Build and use
-------------

Enable ``CONFIG_DMA_ENGINE``, ``CONFIG_DEBUG_FS`` and ``CONFIG_DMABENCH``.
With modules enabled, ``CONFIG_DMABENCH=m`` builds ``drivers/dma/dmabench.ko``.
Build the configured kernel and the tools, for example::

    make O=.build/dmabench -j16
    mkdir -p .build/dmabench/tools/dma
    make -C tools/dma OUTPUT="$PWD/.build/dmabench/tools/dma/"

After booting the built kernel, making debugfs available, and loading the
provider and dmabench, choose an exact channel name from
``/sys/class/dma/``. One command performs allocation, initialization, warmup,
measurement, drain, and optional verification::

    sudo .build/dmabench/tools/dma/dmabench --channel dma0chan0 \
        --transfer-size 65536 --queue-depth 64 --batch-size 16 \
        --buffer-count 1024 --transfers 100000 --warmup-transfers 4096

Add ``--verify`` to check final data, or ``--json`` for machine-readable
configuration and results. ``--help`` lists all options. Numeric values are
decimal integers without unit suffixes. ``--flags 1`` also enables verification;
no other flag bits are defined. Errors are printed on standard error and exit
with a failure status, without a performance result. Interrupted ioctls are
never automatically restarted.

Each ioctl has its own configuration and worker, even when callers share an
open file. Each request reserves exactly the named channel exclusively through
DMAengine. Different available channels may run concurrently. Calls can be
repeated without reloading the module. There is no CPU-copy fallback.

Configuration and resource limits
---------------------------------

================== ========== =================================================
Option             Default    Meaning
================== ========== =================================================
channel            required   Exact channel name, at most 31 characters
transfer-size      65536      Payload bytes per memcpy
queue-depth        64         Maximum copies submitted but not batch-reclaimed
batch-size         16         Maximum submissions per issue and notification
buffer-count       1024       Number of distinct source/destination pairs
transfers          100000     Number of measured copies
warmup-transfers   4096       Untimed copies; zero skips warmup
cpu                -1         Worker CPU; -1 leaves it unbound
timeout-ms         3000       Maximum interval without batch completion progress
flags              0          Bit 0 enables final data verification
================== ========== =================================================

Require ``1 <= batch-size <= queue-depth <= buffer-count``, nonzero transfer
size and measured count, and a positive timeout. The limits per request are
4096 outstanding copies, 65536 buffer pairs, 1 GiB per copy, 16 GiB total
page-rounded source plus destination allocation, and 600000 ms (10 minutes)
without batch completion progress. Allocation accounting must also fit in
``size_t``, making the pool limit smaller on 32-bit kernels. Each phase's
payload count must fit in an unsigned 64-bit integer. Metadata allocation is
bounded by the queue and pool limits. Concurrent requests have independent
limits; sufficient free memory is still required.

Channel names must be nonempty, NUL-terminated, and consist of ASCII letters,
digits, underscores, hyphens or periods. A selected CPU must be online at
worker creation. CPU hotplug may subsequently move the worker; avoid changing
CPU topology during a run. CPU selection controls worker placement only. It
does not guarantee buffer NUMA locality or interrupt affinity.

The requested memcpy size is never rounded or split into multiple DMAengine
transactions. It must satisfy the provider's copy alignment. Each allocation
is rounded up to the kernel page size and must fit the DMA device's maximum
mapping and segment sizes and segment boundary. The returned DMA segment must
cover the allocation and its address must satisfy copy alignment. A provider
can impose additional limits that cause descriptor preparation to fail.

Each source and destination is independently allocated with
``dma_alloc_noncontiguous()`` on ``dmaengine_get_dma_device(chan)``. This API
returns already mapped memory with one DMA segment. Sources use
``DMA_TO_DEVICE``. Destinations use ``DMA_BIDIRECTIONAL`` consistently for
allocation, synchronization, and freeing, because the CPU writes their initial
poison pattern. ``DMA_FROM_DEVICE`` would not guarantee writeback of those CPU
writes on non-coherent platforms (see :doc:`/core-api/dma-api`). With an IOMMU, an
allocation can use scattered physical pages. Without one it can require
contiguous physical memory, so a large individual copy may fail even when a
large pool of smaller buffers succeeds. No device DMA masks or global NUMA
settings are changed. ``allocation_bytes`` is the sum of the page-rounded
sizes passed to the DMA allocator for both pools; it excludes metadata and
any internal allocator or IOMMU rounding overhead.

Measurement and completion
--------------------------

Initialization and DMA mapping finish before warmup. Every source has
deterministic data incorporating its pair index and byte offset. Every
destination starts with the complementary pattern, including when verification
is disabled. The buffers are non-coherent allocations: initialization flushes
the CPU vmap aliases and synchronizes the sg tables for the device. Both pools
remain device-owned through warmup and measurement. The CPU does not access
their contents during either phase.

One kthread prepares and submits copies in adjacent steps. It rotates through
all buffer pairs in order, continuing the rotation across the warmup boundary.
A pair is reused only after its previous batch has been reclaimed. Several
batches may remain outstanding; the worker replenishes capacity as completed
batches are reclaimed from the head. Partial batches are issued when queue
space or the remaining transfer count is smaller than the requested batch.

Each descriptor uses ``DMA_CTRL_ACK``. Only the last memcpy of each submission
batch requests ``DMA_PREP_INTERRUPT`` and installs a callback. Every batch is
followed by ``dma_async_issue_pending()``. There are no per-copy fences,
interrupt-only descriptors, hardware polling, or descriptor reuse. A provider
may produce additional interrupts internally; dmabench controls only the
client's notification requests.

The channel must support ``DMA_MEMCPY`` and ordered completion. Channels
advertising ``DMA_COMPLETION_NO_ORDER`` are rejected. Completion of a batch's
terminal copy establishes that earlier copies have completed according to
the ordered DMAengine contract. ``DMA_PREP_INTERRUPT`` itself provides no
serialization or dependency ordering. Batch records are marked individually
and reclaimed from the head; callback execution order and wakeup coalescing
do not determine the reclamation boundary. Terminal callback errors fail the
run, but success does not establish the success of every earlier copy.
Per-copy error aggregation is not implemented.

Warmup fully drains before measured accounting begins. Timing starts with
``ktime_get_ns()`` immediately before preparing the first measured copy and
ends at the timestamp recorded in the final measured batch's callback.
It includes preparation, submission, issuing, initial queue fill, completion
notification, worker scheduling during the run, and final DMA drain. It
excludes allocation, initialization, warmup, the worker's final wakeup,
termination/synchronization, verification, and cleanup. No overhead is
subtracted. Results measure DMAengine client throughput, not isolated hardware
execution time.

The ioctl returns elapsed nanoseconds, measured submitted and completed copies,
completed payload bytes, measured issue-pending calls, and allocation bytes.
The original effective configuration is returned alongside the results. On a
successful run the submitted and completed counts both equal ``transfers``.
The tool computes MiB/s, GiB/s, and transactions/s from these raw values.
Copying N payload bytes generally causes N bytes of reads and N bytes of
writes: the reported payload rate counts N, not 2N.

Verification and cancellation
-----------------------------

``--verify`` runs after measured DMA and callbacks have quiesced. It
synchronizes the sg tables for CPU access and invalidates the vmap aliases
before comparing source and destination payloads. Only pairs copied during
warmup or measurement are checked, so runs shorter than the pool do not
report untouched destinations as failures. There is no extra correctness
pass before warmup. The final data cannot prove that every repeated copy of
identical data executed correctly. Use :doc:`dmatest` for broader correctness
coverage.

The progress timeout is refreshed by batch callbacks, never by new
submissions. Cancellation checks occur while allocating, initializing,
submitting and verifying; completion waits are interruptible. A signal to the
ioctl caller requests cancellation and wakes the worker. It stops submitting
and quiesces DMA and callbacks before the ioctl returns ``EINTR``. Cancellation
cannot interrupt a provider operation already executing, and the progress
timeout does not bound allocation, verification, or provider termination time.

The provider must implement both ``device_terminate_all`` and
``device_synchronize``. After any submission, including a partially submitted
batch whose terminal descriptor was never submitted, the worker calls
``dmaengine_terminate_sync()`` before releasing buffers or callback storage.
Successful runs also use this operation to quiesce callbacks before cleanup.
The provider's successful termination and synchronization contract is relied
on without provider-specific workarounds.

If termination fails, the ioctl returns ``EIO`` and the kernel logs the
provider error. All request resources, DMA mappings, the channel reservation,
device references, and a permanent dmabench module reference are retained:
DMA or callbacks might still access them. The channel remains unavailable and
normal module unload is prevented until reboot. There is no retry/recovery
ioctl. Even a run whose completion callbacks all arrived is conservatively
retained if termination fails. Normal successful termination releases all
resources. Do not force module removal after a termination failure.

ABI and errors
--------------

``include/uapi/linux/dmabench.h`` defines the 192-byte ``struct dmabench_run``:
a 112-byte configuration followed by an 80-byte result. Its fixed-width,
explicitly aligned fields have the same layout for native and compat callers.
There are no user pointers in the structure. Zero-initialize the whole
structure, fill the configuration, then call ``DMABENCH_RUN``. All reserved
fields must be zero and undefined flag bits are rejected. Non-reserved input
result fields are ignored and initialized by the kernel. No partial results
are returned on error.

=============== ==============================================================
Error           Meaning
=============== ==============================================================
ENODEV          Named memcpy channel absent, busy, or unavailable to reservation
EOPNOTSUPP      Unordered completion or required teardown operations unavailable
EINVAL         Malformed configuration, offline CPU, or unsupported alignment
E2BIG          Resource limit, DMA mapping/segment size, or boundary exceeded
EOVERFLOW      Size or payload accounting cannot be represented
ENOMEM         Buffer, CPU mapping, metadata, or worker allocation failed
EIO            Preparation/submission, terminal callback, timing, or teardown error
ETIMEDOUT      No batch completion progress within the requested interval
EINTR          Interrupted request after safe cancellation
EILSEQ         Final payload comparison failed
EFAULT         Request/result cannot be copied from/to userspace
ENOTTY         Unknown ioctl command
=============== ==============================================================

DMAengine's filtered reservation API does not distinguish absent and busy
channels; both use ``ENODEV``. Worker creation can also return its underlying
kernel error. An error copying results to userspace does not undo a completed
benchmark.

This version does not support user buffers, explicit buffer NUMA placement,
multi-channel requests, duration-based runs, descriptor reuse, hardware polling,
or hardware interrupt moderation controls. Build validation alone does not
establish hardware behavior; test the chosen provider and platform manually.
