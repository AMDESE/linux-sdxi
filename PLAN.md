# SDXI v3 → v4: Plan for addressing review feedback

Feedback on the v3 series came from one human reviewer (Tycho Andersen) and
the Sashiko AI review bot (16 messages). This plan triages every item into
**verified bugs to fix**, a **false positive to rebut**, and **design-level
themes that need a decision** before coding.

Conventions:
- Each item notes the originating patch (`v3 NN/23`) and the file/function.
- Fixes are folded into the originating commit, not appended to the series.
- `[ ]` todo · `[x]` done · `[~]` in progress.
- A trailing `(Sashiko)` marks items raised by the Sashiko AI review bot.
  Unmarked items come from the human reviewer (Tycho) or were added by the
  author. Items found by the AI assistant itself (not raised by Tycho,
  Sashiko, or the author) get an `Assisted-by`-style attribution instead:
  `(Claude:<model-id>)`, where `<model-id>` is whatever model actually found
  the issue (e.g. `claude-sonnet-5`) — check your own identity rather than
  reusing a value from an earlier entry.
- When marking an item done (`[x]`), generate a one-line summary suitable for
  the v3→v4 cover-letter changelog. The summary begins with a `-` bullet and
  ends with an attribution when appropriate, matching the item's tag — e.g.
  `(Sashiko)` or `(Claude:<model-id>)`.

---

## 1. Human reviewer (Tycho) — highest priority

- [x] **Move `pci_disable_sriov()` + `.remove` wiring from patch 09 to patch 03.**
  Patch 03 introduces `.sriov_configure = pci_sriov_configure_simple`, so the
  matching teardown belongs there. Patch 03 now adds `sdxi_pci_remove()` (with
  only `pci_disable_sriov(pdev)`) and `.remove = sdxi_pci_remove`; patch 09's
  `pci.c` change is reduced to adding `sdxi_unregister(&pdev->dev)`.
  - [x] Update **patch 09 commit message**: drop "wire it up via the pci_driver
    .remove callback" (that moves to patch 03); say it is called from the
    existing `.remove` handler.
  - [x] Update **patch 03 commit message**: note it adds the `.remove` hook that
    disables SR-IOV, balancing `.sriov_configure`.

---

## 2. Verified bugs — mechanical, low risk

Each confirmed against the v3 source.

- [x] **v3 21/23 — KUnit `cxt_stop` asserts the wrong union field.** (Sashiko)
  `descriptor_kunit.c` `cxt_stop()` checks `desc.cxt_start.vflags`; should be
  `desc.cxt_stop.vflags`. Copy-paste from the `cxt_start` test.
- [x] **v3 13/23 — KUnit `valid` test double-advances the iterator.** (Sashiko)
  `ring_kunit.c` calls `sdxi_ring_resv_next()` inside `sdxi_ring_resv_foreach()`,
  which already advances; only half the reserved descriptors are checked, and
  `resv.iter` is read in the same expression that advances it. Drop the inner
  `_next()` call (or restructure the loop body).
- [x] **v3 20/23 — dead `clamp_val()` in `sdxi_encode_size32()`.** (Sashiko)
  `descriptor.c`: the `WARN_ON_ONCE(... ) return -EINVAL` above already rejects
  out-of-range sizes, so the following `clamp_val(size, 1, SZ_4G)` is
  unreachable. Remove it. (See also design item E-WARN below re: using WARN for
  client-reachable input.)
- [x] **v3 15/23 — `ida_destroy()` on an uninitialized ida.** (Sashiko)
  `sdxi_alloc_cxt()` never calls `ida_init()`; `ida_init()` happens later in
  `sdxi_admin_cxt_init()` / `sdxi_cxt_new()`. The `__free(sdxi_cxt)` cleanup
  runs `sdxi_free_cxt()` → `ida_destroy(&cxt->akey_ida)` on every early
  allocation-failure path, hitting an uninitialized xarray lock ("spinlock bad
  magic" on debug kernels). Fix: `ida_init()` inside `sdxi_alloc_cxt()` and drop
  the now-redundant later inits.
- [x] **v3 23/23 — IRQ handler ignores hardware errors.** (Sashiko)
  `dma.c` `sdxi_dma_cxt_irq()` completes signaled descriptors without checking
  `sdxi_completion_errored()`, masking failed transfers as success. Surface the
  error to the descriptor's completion status.
- [x] **v3 17/23 — misplaced `dma_rmb()` in `sdxi_completion_signaled()`.** (Sashiko)
  `completion.c`: the barrier fires unconditionally before the signal is read,
  allowing the CPU to speculatively load payload memory before the DMA engine
  has finished writing it. The barrier should come *after* confirming
  `signal == 0`. Also, the signal read in `sdxi_completion_signaled()` lacks
  `READ_ONCE()` and `le64_to_cpu()`, unlike the same read in
  `sdxi_completion_poll()`.
- [x] **v3 14/23 — `sdxi_ring_reserve()` uses uninterruptible `wait_event()` with no timeout.** (Sashiko)
  `ring.c`: if hardware stops advancing the read index (fatal error, hang),
  any thread blocked in `sdxi_ring_reserve()` sleeps in D state indefinitely.
  Should use a timeout variant or an interruptible wait, and propagate the
  error to the caller.
  Switched to `wait_event_killable_timeout()` (1 s): timeout returns
  `-ETIMEDOUT`, a fatal signal propagates `-ERESTARTSYS`, success returns the
  (non-`EBUSY`) `try_reserve` result. Killable rather than interruptible because
  every caller is kernel-internal (admin-ring start/stop/update,
  `sdxi_dma_synchronize`) with no syscall restart semantics, so ordinary signals
  shouldn't spuriously fail a reservation. Does not by itself recover a wedged
  ring — see theme B/E — but stops it from hanging submitters forever.
  Cover-letter one-liner:
  `- Bound the ring reservation wait with a timeout and make it killable. (Sashiko)`
- [x] **v3 12/23 — `sdxi_ring_resv_foreach` evaluates `resv_` multiple times.** (Sashiko)
  `ring.h`: the macro passes `resv_` to `sdxi_ring_resv_reset()` once and to
  `sdxi_ring_resv_next()` twice during loop execution. If a caller passes an
  expression with side effects, those side effects run multiple times. Low
  severity in practice (all callers pass `&resv`), but worth noting for
  correctness.
- [x] **v3 22/23 — restore the `dma_set_mask_and_coherent()` result check.** (Sashiko)
  Reversal of a v2→v3 change (previously triaged as a false positive; now
  actioned). `pci.c` `sdxi_pci_init()` again checks the return of
  `dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64))` and fails probe via
  `dev_err_probe()`, undoing "Drop unneeded dma_set_mask_and_coherent() result
  check. (Frank Li)" from the v2→v3 changelog. A 64-bit mask is effectively
  infallible, but the check is cheap, matches the surrounding probe-error style,
  and keeps probe from proceeding on the theoretical failure. Already present in
  the tree; folds into the PCI-init patch.
  - [ ] Reply to Frank Li / the list explaining why the check is being restored
    (reversing the earlier request), so the change is not a silent regression.
  Cover-letter one-liner:
  `- Restore the dropped dma_set_mask_and_coherent() result check. (Sashiko)`
- [x] **Issue DSC_CXT_UPD when publishing/rescinding a client context.**
  `context.c`: `sdxi_publish_cxt()` and `sdxi_rescind_cxt()` carried
  `todo: need to send DSC_CXT_UPD to admin` markers. Modifying a context's
  CXT_L1_ENT / CXT_CTL while the function may privately cache them requires
  signaling an update (SDXI 1.0 4.3.1.1). New `sdxi_cxt_update()` submits a
  `DSC_CXT_UPD.L1` (covers the L1 subtree, including CXT_CTL) followed by a
  `DSC_SYNC.CXT` on the admin ring and polls for completion. Skipped for the
  admin context, which is published during bootstrap before its own ring is
  operational; `sdxi_admin_cxt_init()` now records `sdxi->admin_cxt` (and its
  devm cleanup) before publishing so `sdxi_cxt_is_admin()` recognizes it.
  Consumes the `cxt_upd` encoder added in the preceding patch. The `akey_upd`
  encoder remains unused for now (no in-tree modification site yet — the AKey
  entry is written post-publish in `dma.c` and wants either its own
  `DSC_AKEY_UPD` or the flagged move into context allocation).
  Cover-letter one-liner:
  `- Signal DSC_CXT_UPD/DSC_SYNC when publishing and rescinding client contexts.`
- [x] **Back out the unused `fn_upd` descriptor support.**
  The `fn_upd` encoder, its `descriptor.h` declaration, `hw.h` definitions
  (DSC_FN_UPD format + `SDXI_DSC_OP_SUBTYPE_FN_UPD`), and its KUnit case had no
  in-tree caller — nothing modifies function-level structures after activation.
  Removed until a real modification site exists. Folds into "sdxi: Add support
  for admin update descriptors."
  Cover-letter one-liner:
  `- Drop the unused DSC_FN_UPD encoder and test (no function-update site yet).`

---

## 3. False positives — rebut on-list

- [ ] **v3 06/23 — `CXT_CTL` DMA pool alignment.** (Sashiko)
  Not a bug. The bot flagged that `device.c` uses `align = size`
  (= `sizeof(struct sdxi_cxt_ctl)`, 64) for the `CXT_CTL` pool while every other
  pool uses `max(size, SMP_CACHE_BYTES)`, allowing false sharing on arches with
  cache lines > 64B. But the false-sharing concern doesn't apply here: unlike the
  other pool-managed objects, context control blocks are not frequently modified
  (written essentially once at context setup), so there is no hot concurrent
  writer to suffer from a shared cache line. The current alignment is
  intentional. Action is documentation, not a behavior change:
  - [ ] Clarify the **patch 06 commit message** to note that `CXT_CTL` is a
    cold object and deliberately not padded up to `SMP_CACHE_BYTES`.
  - [ ] Add a brief **code comment** at the pool setup explaining why the other
    objects align up while `CXT_CTL` does not.

- [ ] **v3 23/23 — "`sdxi_dma_register()` return value ignored."** (Sashiko)
  Intentional, not a bug. The bot asked (Medium) whether ignoring the return is
  deliberate, noting probe succeeds even if the DMA provider interface isn't
  registered. That is the intended behavior: the driver should still probe and
  remain functional (admin context, contexts, etc.) even when the dmaengine
  provider fails to register. Action is to make the intent explicit and confirm
  teardown is correct:
  - [ ] Add a **code comment** at the `sdxi_dma_register()` call in
    `sdxi_device_init()` explaining that failure is non-fatal and probe
    proceeds without a registered DMA provider.
  - [ ] Ensure **device removal** handles the not-registered case correctly
    (i.e. `sdxi_dma_unregister()` / teardown is safe when registration never
    succeeded).
  - [ ] Reply to the bot/list confirming the behavior is intentional.

- [ ] **v3 12/23 — "`do_div()` on every descriptor access."** (Sashiko)
  Not a bug here, and the suggested fix is unsafe. `ring.c`
  `sdxi_desc_ring_entry()` uses `do_div(index, rs->entries)`. The bot's premise
  — that `do_div()` compiles to an expensive `__do_div64` call — is a 32-bit
  concern; this driver is `depends on 64BIT` (Kconfig), where `do_div()` expands
  inline to native `/`/`%` with no function call. Moreover the proposed
  `index & (rs->entries - 1)` is only equivalent to the modulo when `entries`
  is a power of two, which is **not** guaranteed: ring init only enforces
  `entries >= SZ_1K` (`WARN_ON_ONCE(entries < SZ_1K)`), not power-of-two. The
  default (1024) happens to qualify, but the contract does not require it, so the
  mask would silently corrupt the index for a non-power-of-two ring. Keep
  `do_div()`. Reply to the bot/list noting the 64BIT premise and the missing
  power-of-two guarantee.
  (Alternative, not pursued: make power-of-two a hard requirement on `entries`
  and then use the mask — a design constraint we are intentionally not imposing.)

- [x] **v3 09/22 — "missing `pci_free_irq_vectors()` leaks IRQ resources."** (Sashiko)
  Not a leak: the driver uses `pcim_enable_device()`, so the device is
  devres-managed and `pci_alloc_irq_vectors()` is freed automatically on
  teardown. Reply to the bot/list noting this so it is on record.
  **Caveat:** Verify that patch 22/23 (`pci.c`) calls `pcim_alloc_irq_vectors()`
  (devres-managed) rather than `pci_alloc_irq_vectors()` (not devres-managed).
  The rebuttal is only valid if the devres variant is used.
  - Added comment to `sdxi_pci_init()` explaining why it's not a leak,
    cribbed from cxl pci code.

---

## 4. Design-level themes — decide approach before coding

These account for most of the High/Critical findings and collapse into a few
root issues. Each needs a design decision (and likely a list discussion) rather
than a mechanical edit.

- [ ] **A. Quiesce hardware before freeing DMA memory (probe-error + teardown).** (Sashiko)
  Recurs across v3 06/08/09/10/14/22. Two facets:
  - Probe failure after `sdxi_fn_activate()`/`sdxi_dev_start()` lets devres free
    L1/L2/admin DMA while the function may still be (or become) active.
    Candidate: register a `devm` action that stops/resets the function, so it
    runs before the DMA frees in the unwind.
  - `sdxi_unregister()` frees client contexts (and their DMA rings) *before*
    `sdxi_dev_stop()`. Reorder so the hardware is stopped first; also stop each
    client context (`sdxi_stop_cxt()`) rather than just freeing it.

- [~] **B. Completion-poll timeout frees a block the device still owns.** (Sashiko)
  Recurs in v3 17/19/23 (`sdxi_completion_poll()` callers:
  `sdxi_start_cxt`, `sdxi_stop_cxt`, `sdxi_dma_synchronize`). On `-ETIMEDOUT`
  the `__free(sdxi_completion)` cleanup returns the buffer to the DMA pool while
  the engine may still write it.
  **Decision: eliminate per-descriptor completion allocation.** Replace the
  dynamically-allocated completion status blocks (`kmalloc` + `dma_pool_zalloc`
  from `cst_blk_pool`) with a per-context array of `struct sdxi_cst_blk` whose
  length equals the descriptor ring's `entries`, allocated once with the context
  (DMA-coherent, context lifetime). Submitting code "allocates" an entry by
  descriptor ring index (`slot = index % entries`) — the same slot it already
  uses for the descriptor. Rationale:
  - At most `entries` descriptors can be outstanding, so length == ring is
    exactly sufficient and entries never alias between in-flight descriptors.
  - `sizeof(struct sdxi_cst_blk) == 32`, `__aligned(32)`; pack the array at that
    natural 32-byte stride with no per-element padding. The hardware needs only
    32-byte alignment (`sdxi_desc_set_csb()` encodes `addr >> 5` into
    `SDXI_DSC_CSB_PTR = GENMASK_ULL(63, 5)`), so 32 B fully satisfies it. Note
    this drops the cache-line padding the `cst_blk_pool` provided (`align =
    max(size, SMP_CACHE_BYTES)`): adjacent completions may now share a cache
    line and false-share under concurrent device-write / CPU-poll. **Accepted
    for now** — a zero-padding fix (index coloring) is split out as a stretch
    goal in section 6.
  - Nothing is freed per-descriptor, so a timed-out/late write lands in
    still-valid context memory and is simply ignored — the UAF is gone by
    construction. The block is released only at context teardown (after
    hardware is quiesced; see theme A).
  - A wedged slot is self-correcting: the read index never advances past it, so
    the slot is never re-reserved and its block is never reused while the device
    might still own it.
  Side benefits: removes two `GFP_NOWAIT` allocations from the `prep` hot path
  (fewer failure points, cf. theme D), lets the `cst_blk_pool` and the
  `struct sdxi_completion` wrapper go away (`sddesc->completion` becomes a slot
  index), and fixes the current waste of allocating a completion *before*
  `sdxi_ring_try_reserve()` (a `-EBUSY` reserve throws the allocation away).
  **Still required on top of this change:**
  - Timeout *recovery* policy: memory-safety is solved, but a timed-out slot
    wedges the read index, so the ring eventually fills. A fatal timeout should
    escalate to a **context reset** (see theme E) to actually recover.
  - Re-arm + ordering: because slots are reused on wrap, submit must re-set
    `signal = 1` (and clear `flags`) for the slot, ordered before the V-bit /
    doorbell — folds into theme C's barrier discipline.

  **Progress (v4 in-flight):**
  - [x] Per-context completion array (`struct sdxi_cq`, `sdxi_cq_alloc/free`,
    `sdxi_cq_entry`) introduced and allocated with the context — folded into
    patch `pkwn` ("Add completion status block API"). The block is now released
    only at context teardown via `sdxi_free_cxt()`.
  - [x] New `sdxi_cxt_submit()` submission helper (with `sdxi_cxt_kick()` and
    `enum sdxi_submit_flags`) split into its own patch `wmnu` ("Add context
    submission helper"); the doorbell primitive previously open-coded as
    `sdxi_cxt_push_doorbell` is gone.
  - [x] `sdxi_start_cxt()` / `sdxi_stop_cxt()` converted to the per-context
    `sdxi_cst_blk` + `sdxi_cxt_submit()` path (no more `sdxi_completion_alloc()`
    / `__free(sdxi_completion)`) — folded into patch `xmlo` ("Provide context
    start and stop APIs"). Every revision `pkwn..qylz` build-verified.
  - [x] **`dma.c` converted** (re-derived on this line, not the earlier
    `uyqq`/`tkts` attempt). The `prep`/`synchronize`/IRQ/`tx_status` paths now
    draw each issued descriptor's completion block from the per-context cq array
    (`sddesc->cst`, bound at issue time by ring slot) instead of a
    dynamically-allocated one. The attach primitive is factored out of
    `sdxi_cxt_submit()` as `sdxi_cxt_attach_cst()` (own patch `zkxs`) so the
    drain path can bind a slot's block before publishing the descriptor; the
    conversion itself is patch `yryk`. `tx_status` drops its now-dead
    `sddesc->cst` NULL check — `vchan_find_desc()` only returns issued
    descriptors, which always have a `cst`. `issue_pending` keeps its
    make-valid-then-single-kick batch.
    Cover-letter one-liners:
    `- Factor sdxi_cxt_attach_cst() out of the context submit helper. (Sashiko)`
    `- Draw descriptor completion blocks from the per-context array. (Sashiko)`
  - [x] **Dead old completion API removed** — `sdxi_completion_alloc/free/
    attach/check/poll`, the `DEFINE_FREE`, and the unused `sdxi` back-pointer in
    `struct sdxi_completion` are deleted from `completion.{c,h}` (patch `qmyk`).
    The now-unused `CST_BLK` `cst_blk_pool` and its `sdxi_dev` field are removed
    separately (patch `vkqo`). `yryk`, `qmyk`, `vkqo` each build independently.
    Cover-letter one-liners:
    `- Drop the unused per-descriptor completion API. (Sashiko)`
    `- Remove the unused CST_BLK dma_pool. (Sashiko)`
  - [x] **Wedged-context memory safety on the submission paths.** The blocking
    ring reservation is now bounded and killable (patch `qxop`, item v3 14/23):
    a wedged ring returns `-ETIMEDOUT` instead of hanging a submitter forever.
    `sdxi_dma_synchronize()` stops the context on any drain failure (except
    `-ERESTARTSYS`) before flushing IRQ/tasklet, so the device is guaranteed to
    have finished all transfer-buffer accesses before it returns — closing the
    buffer UAF a wedged device could otherwise cause (patch `wpwl`; see theme D).
    Cover-letter one-liner:
    `- Stop a wedged context in device_synchronize() before returning. (Sashiko)`
  - Submit re-arm is handled: `sdxi_cxt_attach_cst()` re-inits the slot's
    `signal` on reuse. The barrier ordering around it stays with theme C.
  - [ ] Full timeout *recovery* — detecting a wedged context and escalating to a
    **context reset** so the ring can be reused — is **deferred past v4**. Memory
    safety is solved (above); reviving a dead channel needs the reset ladder
    (themes E/F).

- [ ] **C. Descriptor-ring write-index ordering and barriers.** (Sashiko)
  v3 12/13. `sdxi_ring_state_store_widx()` publishes the hardware-visible write
  index with no `dma_wmb()` before it, and `ring.c` has no barriers at all.
  Concerns: (1) ordering between descriptor payload writes and the write-index
  store, and before the doorbell; (2) on ring wrap, a reused slot may still have
  a stale Validity bit set, so a concurrent reserver could let the device run an
  old descriptor. Decide on barrier placement and whether to clear V-bits under
  the reservation lock (or otherwise decouple reservation from publish).

- [ ] **D. dmaengine provider semantics (`dma.c`).** (Sashiko)
  v3 23. Several `dmaengine` contract issues; decide which are real vs. accepted
  limitations of "basic support":
  - [x] `sdxi_dma_terminate_all()` ignores `desc_issued` and does not stop the
    hardware context — issued transfers keep running into possibly-freed buffers.
    **Addressed** by stopping the context in `sdxi_dma_synchronize()` on drain
    failure (patch `wpwl`): the stop is the sleepable barrier dmaengine allows
    (`terminate_all` may be called in atomic context, so it can't sleep on the
    admin ring), and after `terminate` + `synchronize` the device is guaranteed
    done with the buffers. `terminate_all` itself still only frees not-yet-issued
    work, by design. Residual: if the admin ring is itself dead the stop can't
    complete — that needs the reset ladder (themes E/F, deferred).
  - [ ] `sdxi_tx_status()` can complete out of order and returns `DMA_ERROR`
    without unlinking the errored descriptor. (Split out from the v3 23 IRQ
    handler error fix, which now sets `tx_result` and completes on error.)
    Reconcile the poll path with the IRQ path: on error `sdxi_tx_status()`
    returns `DMA_ERROR` early *without* `list_del()` / `vchan_cookie_complete()`
    (so the errored descriptor is never cleaned up) and *without* setting
    `vdesc.tx_result.result`, so the two completion paths disagree on the same
    error.
  - Freeing a prepared-but-unsubmitted descriptor leaves reserved ring slots
    with the V-bit clear, which can hang the channel.
  - [x] `sdxi_dma_synchronize()` error paths can leave uninitialized ring holes
    and bypass `vchan_synchronize()`. **Addressed** (patch `wpwl`): the function
    no longer early-returns on reservation failure — it always reaches
    `synchronize_irq()` + `vchan_synchronize()`, and a failed reservation
    reserves nothing, so it leaves no partially-initialized ring slots.

- [ ] **E. `sdxi_dev_stop()` state-machine gaps.** (Sashiko)
  v3 04/09. Missing explicit `SDXI_GSV_STOP` case falls to `default` → spurious
  `RESET`, after which the poll samples the stale `STOP` state and returns
  success while the reset is still in flight. Also: a soft-stop timeout returns
  `-ETIMEDOUT` without escalating to hard stop/reset, which can break the
  kexec-recovery intent. Add the `STOP` case and decide escalation behavior.

- [x] **E-WARN. `WARN`/`WARN_ON_ONCE` on client-reachable input.** (Sashiko)
  v3 13/20. `sdxi_encode_size32()` uses `WARN_ON_ONCE()` to validate transfer
  size, but `dmaengine_prep_dma_memcpy()` does not pre-filter size, so a client
  can trigger a stack dump (or panic with `panic_on_warn`). Return `-EINVAL`
  without `WARN`. Relatedly, the `invalid` KUnit test (v3 13) deliberately trips
  a `WARN_ONCE` in `sdxi_ring_try_reserve()`, polluting the log / risking
  `panic_on_warn` in CI — decide whether to restructure the test or keep the
  WARN as a genuine programming-error guard reached only by the test.

- [ ] **F. Context recovery after a descriptor/transfer error.**
  Split out from the v3 23 IRQ handler fix. That fix now *reports* a descriptor
  error to the client (via `tx_result` / `callback_result`), but does nothing to
  recover the hardware context. If an SDXI descriptor error halts the context,
  subsequent descriptors never signal, the ring wedges, and reservers block —
  the same dead-context state the completion-poll timeout hits. Decide: does a
  descriptor error halt the context, and if so, detect it and reset/recover the
  context (reusing the reset machinery from themes B/E) rather than leaving the
  channel silently stuck. Relates to B (fatal → reset) and E (escalation).

- [x] **G. Consolidate the descriptor ring, write index, and context status
  into one kernel-only flex-array `struct sdxi_sq`.** Author-initiated rework
  (not review feedback). Today each submission queue makes three separate DMA
  allocations in `sdxi_alloc_cxt()` (`context.c`): `desc_ring` via
  `dma_alloc_coherent`, plus `write_index` and `cxt_sts` from the
  `write_index_pool` / `cxt_sts_pool` dma_pools. **Reappropriate the name
  `struct sdxi_sq`** (today a software bag of pointers) for a single
  DMA-coherent flex-array struct holding all three, mirroring `struct sdxi_cq`
  (theme B) and giving the idiomatic SQ/CQ pairing. `sdxi_sq` is explicitly the
  **kernel's** per-context submission bundle: user-space-exposed contexts map
  their indexes/status into userspace and never allocate an `sdxi_sq`, so
  folding the architected `CXT_STS` (context status, which carries the SQ
  `read_index` *and* context `state`) under the SQ name is intentional here, not
  a layering blur.
  ```c
  /* DMA-coherent; kernel contexts only; paired with sdxi_cq. */
  struct sdxi_sq {
          dma_addr_t handle;                       /* base of this allocation */
          u32 count;                               /* slots; see __counted_by note */
          __le64 write_index;                      /* driver -> hw (producer) */
          struct sdxi_cxt_sts cxt_sts              /* hw -> driver (read_index, state) */
                  ____cacheline_aligned;
          struct sdxi_desc ring[] __counted_by(count);   /* 64-aligned via sdxi_desc */
  };
  ```
  - **Alignment.** `struct sdxi_desc` is `__packed __aligned(64)` (`hw.h`), so
    `entry[]` starts at a 64-byte-aligned offset — the *only* alignment the ring
    base requires (`DESC_RING_BASE_PTR_SHIFT` = 6). `dma_alloc_coherent` returns
    a page-aligned base, so all three hardware pointers derive from `handle +
    offsetof(member)`: `cxt_sts` (16-aligned, `CXT_STATUS_PTR_SHIFT` = 4) and
    `write_index` (8-aligned, `WRT_INDEX_PTR_SHIFT` = 3) both land on
    `SMP_CACHE_BYTES` boundaries, comfortably satisfying their shifts. Expose one
    accessor each — `sdxi_sq_ring_dma()`, `sdxi_sq_write_index_dma()`,
    `sdxi_sq_cxt_sts_dma()` — each returning `handle + struct_offset(...)`, in the
    style of `sdxi_cq_entry()`. `configure_cxt_ctl()` sources all three from
    these instead of the old `*_dma` fields, and `ds_ring_sz` becomes `sq->count`
    (64-byte units == slot count, since `sizeof(struct sdxi_desc) == 64`; guard
    with a `static_assert`).
  - **Cache-line isolation of `cxt_sts` is required, not optional** — this
    resolves the theme C interaction the earlier draft left open. `cxt_sts` is
    device-written (`read_index`) while `write_index` is CPU-written; today the
    per-pool `align = max(size, SMP_CACHE_BYTES)` keeps them on separate lines, so
    the folded struct must reproduce that. Only `cxt_sts` needs
    `____cacheline_aligned`: `handle`/`count`/`write_index` are all CPU-side
    (the device never reads `handle`, and `count` reaches it as a copied
    `ds_ring_sz`, not a live read), so they share the leading line with the
    driver-written `write_index` — the false-sharing pair that must be split is
    CPU-written `write_index` vs device-written `cxt_sts`. `ring[]` keeps its own
    64-byte alignment. Net lead-in is 128 B before the ring — negligible against a
    ≥64 KB ring — and legal precisely because the ring base needs only 64-byte,
    not size-, alignment.
  - **`__counted_by(count)` on the hot path.** `sdxi_ring_state` holds a bare
    `struct sdxi_sq *` and `sdxi_desc_ring_entry()` indexes `sq->ring[]` directly
    (`do_div(index, sq->count)`), so the ring access is a real flex-array
    subscript and `__counted_by` bounds-checks it in hardened builds. The `count`
    field also satisfies `struct_size()`. Cost: the `do_div` divisor now reads
    `sq->count` from coherent memory (cached WB on x86; an uncached load per op on
    a non-coherent arm64 device) rather than a cached copy in normal memory. That
    tradeoff is accepted in favor of using `sdxi_sq` directly — the descriptors
    live in that same region anyway, and duplicating the count/ring pointer into
    `sdxi_ring_state` reintroduces exactly the indirection this rework removes.
  - **Struct/ownership shuffle.** The old software `struct sdxi_sq` (bag of
    pointers + `*_dma` handles) is dissolved — its role collapses into the new
    DMA `sdxi_sq`. `sdxi_ring_state` (`ring.h`) shrinks to its software-only
    fields (lock, wqh) plus a `struct sdxi_sq *`, reaching the indexes, count, and
    ring through it; `sdxi_ring_state_init()` takes a `struct sdxi_sq *`. Add
    `sdxi_sq_alloc()` / `sdxi_sq_free()` (`struct_size`-based, like
    `sdxi_cq_alloc/free`); `context.c` calls them and frees at context teardown.
  - Removes the `write_index_pool` and `cxt_sts_pool` dma_pools entirely
    (`device.c`); three DMA allocations become one — mirrors theme B's collapse
    of `cst_blk_pool`. `cxt_ctl` stays separate (L1-referenced context control
    block, not submission-queue state).
  - KUnit (`ring_kunit.c`): tests build a plain-`kmalloc` `struct sdxi_sq`
    (`struct_size`, `count` set, `handle` 0 — no device, doorbell `NULL`) and
    pass it to `sdxi_ring_state_init()`; add a small helper. Isolation-testability
    is preserved (no DMA required).
  - Interacts with theme C: barrier placement around publishing `write_index`
    remains theme C's call; this item fixes only the *layout* (separate cache
    lines), not the ordering.

- [x] **H. Split the channel's shared AKey and push interrupt setup into the
  context.** Author-initiated (resolves the standing `dma.c`
  `alloc_chan_resources()` TODO: "this irq and akey setup should perhaps all be
  pushed into the context allocation"). Two coupled decisions:
  - **Two AKeys, not one.** A channel used a single `AKEY_ENT` both to route its
    completion interrupt and to name the address space for copy src/dst. One
    entry is legal for both, but the roles touch disjoint fields (AKEY_ENT
    Table 3-7: `iv`/`intr_num` vs. `pasid`/address space) and the combined entry
    shipped a data-access AKey with a live `intr_num`. Use a dedicated interrupt
    AKey (`vl`/`iv`/`intr_num`) and transfer AKey (`vl` only; `iv=0`, `pv=0` →
    context-default translation). Spec-checked: `tgt_sfunc=0` is correct for the
    interrupt AKey (local function; `intr_num` is only meaningful when
    `tgt_sfunc=0`, per Table 3-7), and DSC_INTR (Table 6-12) reads only `akey`.
    Sets up per-address-space transfer AKeys later (the parked `DSC_AKEY_UPD`
    encoder's eventual user) without disturbing the fixed interrupt path.
  - **Interrupt setup is a context capability.** The vector, irq, and interrupt
    AKey are properties of the context that raises the interrupt, not of the
    dmaengine channel. `sdxi_cxt_request_completion_irq()` /
    `sdxi_cxt_free_completion_irq()` bundle them (provider still supplies its own
    handler, so no layering inversion); the polled admin context simply never
    calls it. Collapses the four-step goto ladder in `alloc_chan_resources()`.
    The channel retains only its transfer AKey (a data-path resource).
  Changelog: `- sdxi: give DMA channels separate interrupt/transfer AKeys and
  move completion-interrupt setup into the context.`

- [x] **I. Split `struct sdxi_cxt` into base + admin + dma context types.**
  Author-initiated follow-up to H. One struct served both the admin context
  (context 0) and dmaengine client contexts, discriminated at runtime by
  `sdxi_cxt_is_admin()` and guarded by WARNs. Introduce a common `struct
  sdxi_cxt` base embedded as the first member of `struct sdxi_admin_cxt` and
  `struct sdxi_dma_cxt`; client-only state (`id`, `akey_ida`, and the
  completion irq) moves onto the dma leaf, and client-only ops take
  `struct sdxi_dma_cxt *` so the `is_admin`/WARN guards delete outright (the
  type system enforces the rule). The base keeps the akey *table* — context 0
  still needs a valid `CXT_L1_ENT.akey_ptr` (see the `sdxi-admin-akey-table`
  finding); only the akey *ida* is client-specific. Done as two commits (type
  introduction, then relocating the completion irq onto the dma leaf).
  - Deferred: admin's own interrupt setup (error-log / `DSC_ADM_INTR`); an
    intermediate `client` tier for future userspace contexts; folding
    `free_completion_irq` into `sdxi_cxt_exit()` + storing the irq cookie.
  Changelog: `- sdxi: split the context object into distinct administrative and
  dmaengine client types over a shared base.`

---

## 5. Series-wide wrap-up

- [ ] Update the **cover letter** (v3 00/23) for v4: note the SR-IOV
  teardown move, the bug fixes above, and the v3→v4 changelog.
- [ ] Re-run KUnit (`descriptor_kunit`, `ring_kunit`) after the test fixes.
- [ ] Build + functional test on hardware before sending v4.
- [ ] Reply to outstanding review threads (Tycho ack; false-positive rebuttal).

---

## 6. Stretch goals — later follow-up (not blocking v4)

- [ ] **Eliminate completion-array false sharing without padding (index coloring).**
  Follow-up to theme B. The per-context completion array (section B) is packed at
  the 32-byte struct stride, so adjacent completions can share a cache line — a
  potential false-sharing cost under concurrent device-write / CPU-poll that the
  old `cst_blk_pool` avoided via `align = max(size, SMP_CACHE_BYTES)`. Recover
  that property *without* paying the ~2× memory of per-element cache-line padding
  by permuting (transposing) the index so adjacent descriptors map to different
  cache lines:
  - With `PER_LINE = max(1, SMP_CACHE_BYTES / 32)` and
    `LINES = DIV_ROUND_UP(entries, PER_LINE)`, map logical slot `s` to physical
    offset `phys(s) = (s % LINES) * PER_LINE + (s / LINES)`; size the array to
    `LINES * PER_LINE`. Consecutive descriptors then occupy consecutive lines;
    two slots share a line only when `LINES` apart (~half a ring). Since the
    device completes a context's ring in slot order, its sequential
    completion-writes step across distinct lines and never dirty the line the CPU
    just read for the previous descriptor.
  - Compute `phys(s)` **once at prep/attach** (when encoding `csb_ptr` and
    stashing the handle in `sddesc`) so the poll / `tx_status` read path does no
    extra arithmetic. The one transpose per descriptor is a single `do_div`
    (degrades to shift+mask when `entries`, hence `LINES`, is a power of two).
  - `PER_LINE == 1` makes `phys()` the identity — no special-casing.
  - Add a KUnit case asserting `phys` is a bijection over `[0, entries)` and that
    `phys(s)` / `phys(s+1)` differ in cache line.
  - Motivation grows once **ring size becomes configurable**: padding's waste is
    `entries × (SMP_CACHE_BYTES − 32) × nr_contexts` (unbounded), while coloring
    keeps the array cost intrinsic at one 32-byte block per slot.
