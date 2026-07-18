# SDXI driver work (v3 → v4)

This driver is intended for upstream. Consult
Documentation/process/coding-assistants.rst for important rules.

This is a **jj workspace** on a Linux kernel tree, not a plain git
checkout.

## VCS
- Use `jj`, not `git`. The git dir here is only a backend store.
- Fixes for review feedback are **appended as temporary commits**; the human
  (Nathan) folds them back into the originating commit manually. Don't squash
  or rewrite history yourself.
- Every commit you write must carry an `Assisted-by:` trailer per
  Documentation/process/coding-assistants.rst:
  `Assisted-by: Claude:<model-id>`, where `<model-id>` is whatever model is
  actually running the session (e.g. `claude-sonnet-5`) — check your own
  identity rather than copying a value from an old commit or this file.
  Never add `Signed-off-by` — only Nathan can certify the DCO.
- Keep functional changes separate from refactors/pure code movement — put
  them in different commits. Multiple commits per work session are normal;
  split a change further whenever that can be done without introducing a
  regression (a broken intermediate state). Squashing commits together later
  is easy, splitting them after the fact is not, so split proactively when
  in doubt.
- `PLAN.md` and `CLAUDE.md` are tracked (for backup/history), but aren't
  part of the patch series. Keep their edits in their own commit(s), never
  mixed with driver-source changes, so they're trivially excluded when
  generating patches for submission.

## Active task
- Addressing v3 review feedback for the SDXI DMA engine driver.
- Correcting other issues as they arise, including driver nonconformance
  to the SDXI spec.
- The latest released SDXI specification is 1.0a. There is a copy at
  ~/docs/SNIA-SDXI-Specification-v1.0a.pdf. Pages 5-7 have the table of
  contents. Prefer this for questions about SDXI device behavior. The spec
  is authoritative.
- A draft of a future SDXI specification is at
  ~/docs/SDXI-Specification-v1.0.3r5.pdf. This may be useful to check when
  there are ambiguities in the released version or questions about
  future changes. Prefer the released version; the driver is intended to
  support only 1.0 features at this point.
- Driver lives in `drivers/dma/sdxi/`.
- Triage + status of every review item, plus the attribution and
  cover-letter-changelog conventions, are in `PLAN.md`. Keep it in sync as
  you work, including adding items you find yourself (e.g. spec
  nonconformance not raised by either reviewer) under the same conventions.

## Build / test
- If there are configuration errors or missing packages, ask the human to
  resolve the situation. Do not attempt to fix these yourself. Do not
  download or install additional software e.g. from GitHub or package
  indexes. Absolutely do not use sudo.
- There are two build scripts to use. Do not invoke make directly.
- `~/src/junk/sdxi-kunit` runs the kunit suite for the driver. Invoke it
  without arguments. Run it after any code change.
- `~/src/sdxi-guest-test/deploy.sh` builds and boots the kernel with the
  driver in a KVM guest on a remote host. There is a test script in the
  image that runs after booting. The script runs the unit tests and also
  uses the dmatest exerciser to check the sdxi driver. Run it once a change
  is considered done, before moving on to the next one — no commit may leave
  this script broken. The script is configured to exit with a 0 status only
  if no problems were found; nonzero exit status implies a failure of some
  kind. dmatest-specific failures are expected unless the `dmaengine/dmatest`
  bookmark is an ancestor of the working commit; check with:
  `jj log -r 'bookmarks(exact:"dmaengine/dmatest") & ::@' --no-graph`
  (non-empty output means it's included). Merging that bookmark in is the
  human's responsibility. Run the script in this way:
  - `~/src/sdxi-guest-test/deploy.sh $PWD kenya-0159host --  -device
    vfio-pci,host=0000:01:02.1 -device vfio-pci,host=0000:01:02.2`

## Style
- Kernel coding style throughout. Kernel conventions take precedence over
  general readable-code guidance for code in this tree.
- Comments, when used at all, should be concise. They should not refer to
  past decisions or earlier versions of the work; they should explain
  decisions in terms of the present design of the driver. There are
  already some overly verbose comments in the code, consider editing or
  removing them altogether when they are involved in changes. Unusual or
  subtle decisions deserve comments; code that is merely following
  established kernel conventions and rules often does not.
