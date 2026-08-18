# mlr3hf — Adversarial Package Audit

| | |
|---|---|
| **Target** | mlr3hf 0.0.0.9000 |
| **Commit** | a3898f5 |
| **Date** | 2026-08-18 |
| **R** | 4.6.1 |
| **Scope** | ~1,000 LOC across 10 R files |

**56 findings — 7 critical, 21 high, 20 medium, 8 low — plus 9 hypotheses that were tested and disproven.**

Findings are marked **[CONFIRMED]** when reproduced by execution, and **[STATIC]** when the
conclusion comes from reading alone. Nothing in this report has been fixed; it is diagnosis only.

---

## Summary

The package is small and the code reads cleanly, which is why the results below are worth taking
seriously: nothing here is stylistic. Three findings stand out above the rest.

**First, a remote server chooses where this package writes files.** The `ETag` and `x-repo-commit`
response headers are pasted straight into filesystem paths with no validation, and `fs::path()` does
not collapse `..`. A hostile or compromised host can create `~/.Rprofile` with content it controls,
which is arbitrary code execution on the user's next R start. Two agents reproduced this
independently against a real HTTP server on localhost.

**Second, the package's headline feature does not exist in its public API.** The Title, Description
and README all promise conversion into mlr3 Tasks. `grep -rn 'Task' R/` returns zero hits. Both data
backends are marked `@noRd` and are absent from `NAMESPACE`; the only things a user can reach are
file paths.

**Third, the test suite is measuring almost nothing.** It reports 75 passing expectations, but 14 of
18 backend tests survive a mutation that destroys every value read from disk, and a bare
`expect_error()` is currently certifying a documented feature that fails 100% of the time. The vcr
cassettes create the appearance of network isolation while four tests quietly download real bytes
from huggingface.co on every run.

| Surface | Crit | High | Med | Low | Verdict |
|---|---|---|---|---|---|
| **Security** — path & network | 2 | 5 | 6 | 0 | Remote peer controls local paths |
| **Correctness** — cache & backends | 3 | 7 | 6 | 4 | Silent data loss; offline mode dead |
| **Packaging** — CRAN & CI | 0 | 4 | 5 | 3 | Fails on a declared-deps-only install |
| **Tests** — coverage & rigour | 2 | 5 | 3 | 1 | Green, but not load-bearing |

---

## Surface 01 — Security: the remote server decides where you write

Every path component below the cache root — `etag`, `commit_hash`, `file_name`, `revision`, `split`
— is concatenated with `fs::path()` with zero validation, and three of those five arrive from the
HTTP peer.

### S1 · CRITICAL · [CONFIRMED] — A malicious `ETag` header writes an arbitrary file, giving code execution

`R/utils.R:47-54` · `R/cache_hfhub.R:153` · `R/cache_parquet.R:149`

`normalize_etag()` strips only `"` and `W/`. The result becomes
`fs::path(storage_folder, "blobs", etag)`, and `fs::path()` preserves `..`. Two agents reproduced
this end-to-end with no stubbing, using a small HTTP server on 127.0.0.1 and
`options(mlr3hf.hub_url=…)` — the exact position of a compromised hub, a MITM, or a user who set
`MLR3HF_HUB_URL`.

```
server responds:  ETag: "../../../../home/.Rprofile"
                  x-repo-commit: 5555…5555
                  body: cat('OWNED\n')

R> cache_hfhub("scikit-learn/iris", "iris.csv")
→ returns normally, no warning
→ <home>/.Rprofile created with the attacker's bytes
```

Honest constraint: this creates files, it does not overwrite them — `if (fs::file_exists(blob_path))`
short-circuits first. That is still sufficient for `.Rprofile`, `.ssh/authorized_keys` or an autostart
entry when absent. Note also that the default cache is `~/.cache/huggingface`, the same directory
Python's `huggingface_hub` uses — so this can poison the shared cache too.

### S2 · CRITICAL · [CONFIRMED] — `x-repo-commit` is never validated, placing directories and symlinks anywhere

`R/cache_hfhub.R:154-165, 189` · `R/cache_parquet.R:147-150`

The `^[0-9a-f]{40}$` check is applied only to the *user's* `revision`, never to the server's commit
hash, which then feeds `fs::dir_create(recurse = TRUE)` and the snapshot path.

```
x-repo-commit: ../../../../home2   ETag: benign-etag-1
R> cache_hfhub("scikit-learn/iris", "planted.txt")
→ <home2>/planted.txt  — symlink to attacker-controlled bytes
```

### S3 · HIGH · [CONFIRMED] — The same header turns `cache_hfhub()` into an arbitrary local-file read

`R/cache_hfhub.R:154-176` · `R/backend_hfhub.R:7-16`

Because the traversed snapshot path is returned early when it exists, the hub can make the package
hand back any readable local file with a `.csv`/`.tsv`/`.parquet` name — which `backend_hfhub()` then
parses into an mlr3 backend, pulling its contents into the session.

```
x-repo-commit: ../../../../home2
R> readLines(cache_hfhub("scikit-learn/iris", "secrets.csv"))
[1] "SECRET-TOKEN=hf_abc123"
```

### S4 · HIGH · [CONFIRMED] — A traversing `revision` truncates and overwrites an existing file

`R/cache_hfhub.R:167-172`

This is the only confirmed *overwrite* primitive: `writeLines(commit_hash, ref_path)` where the
target comes from `revision` and the content comes from the server. A two-line `.bashrc` was replaced
with a single server-chosen line.

### S5 · HIGH · [CONFIRMED] — The auth token is sent to any host named in a JSON response body

`R/download_parquet.R:34-40, 48-57`

`download_parquet()` takes URLs verbatim from metadata JSON and calls `get_parquet()`, which attaches
`hub_headers()` — including `Authorization: Bearer` — with no origin check. Because this is a
response body rather than a redirect, libcurl's header-stripping protection does not apply. Confirmed
with two localhost servers: the token crossed origins.

```
:8901 /parquetjson/…/parquet     auth: Bearer FAKE-TEST-TOKEN-123
:8902 /exfil/train-00000.parquet  auth: Bearer FAKE-TEST-TOKEN-123
```

Mitigating: `download_parquet()` currently has no callers (see F16 / R4). It is a loaded gun rather
than a fired one.

### S6 · HIGH · [CONFIRMED] — A single env var redirects all authenticated traffic, over cleartext HTTP if asked

`R/defaults.R:1-6, 15-20`

`MLR3HF_HUB_URL` accepts `http://` with no scheme validation and no warning. An entry in a CI config
or a `.Renviron` is enough to send the Bearer token in the clear — and to hand an attacker the write
primitive in S1.

### S7 · HIGH · [CONFIRMED] — No HTTP call anywhere sets a timeout

`R/utils.R:193-196` and every httr call site

`grep -rn timeout R/` returns nothing; `curl::new_handle()` sets only progress options. Against a
server that accepts the connection and sleeps, R was still blocked when an external 45-second kill
fired. Retries multiply the stall.

### S8 · MEDIUM · [CONFIRMED] — Caller-supplied `file_name` also escapes the cache

`R/cache_hfhub.R:67-72, 154-159`

No sanitization at all: `file_name = "../../../../../home4/dropped.csv"` planted a symlink outside the
cache. An absolute `file_name` does *not* escape, because `fs::path()` drops the leading slash and
joins.

### S9 · MEDIUM · [CONFIRMED] — Unescaped `repo_id` pivots the authenticated request to another Hub endpoint

`R/utils.R:14-17`

`hub_url()` escapes only spaces. `repo_id = "../../api/whoami-v2?"` caused curl to normalize the
dot-segments and issue `GET /api/whoami-v2` — a token-introspection endpoint — with the Bearer token
attached; `download_hfhub()` would write the response to disk. A `#` silently truncates revision and
filename, fetching a different resource than requested. Host pivoting is *not* possible, and CRLF is
rejected by curl.

### S10 · MEDIUM · [CONFIRMED / partly STATIC] — Datasets-server JSON supplies path components in `cache_parquet`

`R/cache_parquet.R:112-113, 131-150` · `R/download_parquet.R:29-35`

A `split` of `"../../../../../pvictim/injected"` created directories outside the cache before the
download step failed. The file-placement half is static-only — the harness could not serve the
traversal URL — but the path-joining code is byte-identical to the confirmed `cache_hfhub` case.

### S11 · MEDIUM · [CONFIRMED] — `list_datasets` follows a `Link: rel="next"` header to any host

`R/list_datasets.R:98-113`

Rows fetched from an attacker-named host were merged into the returned `data.table` with no origin
check. Mitigating: this path passes `headers = NULL`, so no token accompanies the SSRF — which also
means `list_datasets` can never see gated or private datasets.

### S12 · MEDIUM · [CONFIRMED] — Error-response bodies are written to disk and echoed into logs

`R/download_hfhub.R:20-22` · `R/download_parquet.R:52-59` · `R/download_desc.R:34`

`httr::write_disk()` commits a 404 body to `destfile` before the status check runs, so a poisoned
file is left behind. Separately, `download_desc()` interpolates the entire untruncated response body
into its abort message — server-controlled content straight into CI transcripts. `curl_download()` in
`download_file()` behaves correctly here and leaves no blob.

---

## Surface 02 — Correctness: silent data loss and a feature that never worked

The failures that matter most here are quiet ones: the package returns successfully while giving back
less data than it fetched, or a path to a file that is not there.

### F1 · CRITICAL · [CONFIRMED] — Multi-shard Parquet splits are silently truncated to their first shard

`R/backend_parquet.R:11` · `R/cache_parquet.R:196-199`

`lapply(path, nanoparquet::read_parquet)` iterates over *list elements*, but `cache_parquet()` returns
each split as a character *vector* of shard paths. `read_parquet()` on a length-2 path reads only the
first file — no error, no warning. Every sharded dataset, which means every large one, loses data.

```
input : train = c(train.parquet[3 rows], train-2.parquet[2 rows])
        test  = test.parquet[3 rows]
result: backend nrow = 6   splits: test=3, train=3  (should be 5)
direct: nanoparquet::read_parquet(c(f1,f2)) → 3 rows, NO warning
```

### F2 · CRITICAL · [CONFIRMED] — `cache_hfhub(local_files_only = TRUE)` has never worked

`R/cache_hfhub.R:77-98` (assign) vs `:104` (use)

Four agents landed on this independently. `etag`, `commit_hash`, `url` and `expected_size` are bound
only inside `if (!local_files_only)`; line 104 then evaluates `if (is.null(etag))` unconditionally.
The documented offline mode fails on every call, *including with a fully warm cache*.

```
R> cache_hfhub("scikit-learn/iris", "Iris.csv", local_files_only = TRUE)
Error: object 'etag' not found   # even with refs/ and snapshot present
```

Two aggravating details. If `etag` alone were fixed, `url` would silently resolve to `base::url` — a
function — and be passed as the download URL. And the test at `test-cache_hfhub.R:8-18` is a bare
`expect_error()` with no `regexp`, so it passes on this error and has been certifying the bug as
working behaviour. Coverage of lines 104-142 is 0%.

### F3 · CRITICAL · [CONFIRMED] — Nothing exported produces an mlr3 Task — or even a backend

`DESCRIPTION:2` · `NAMESPACE` · `R/backend_hfhub.R:7` · `R/backend_parquet.R:10`

`grep -rn 'Task' R/` returns no hits at all. `NAMESPACE` exports exactly `cache_hfhub`,
`cache_parquet`, `download_desc`, `list_datasets` — all of which return file paths or raw metadata.
Both backends are `@noRd` and reachable only via `:::`. The Title, Description and README all promise
the conversion.

### F4 · HIGH · [CONFIRMED] — Reconstructing the shard URL breaks every partially-converted dataset

`R/cache_parquet.R:84` (API url discarded) · `:116-118`

The authoritative `url` from the API is commented out and rebuilt as `{config}/{split}/{filename}`.
For datasets HF converts only partially the real directory is `partial-<split>`. Verified against the
live API and Hub for `allenai/c4`:

```
built by code:  …/af/train/0000.parquet          HTTP 404 EntryNotFound
given by API:   …/af/partial-train/0000.parquet  HTTP 302 OK
```

All 1,006 shards are uncacheable, and the user gets the misleading abort at `:126-128` telling them to
correct their input. The "doubled path segment" variant originally suspected is refuted — `filename`
is always a basename in real responses.

### F5 · HIGH · [CONFIRMED] — Downloads are never verified, and `expected_size` is always `NULL`

`R/cache_hfhub.R:97` · `R/utils.R:84`

`metadata$expected_size` reads a field that `get_file_metadata()` returns as `size`; `$` partial
matching cannot bridge the two, so the value is always `NULL`. More importantly, nothing anywhere
compares the downloaded size — or any hash — against the metadata. The blob is *named* by its ETag but
never *checked* against it, so a truncated download is stored and served forever under a
correct-looking name. Python's `huggingface_hub` raises on this.

### F6 · HIGH · [CONFIRMED] — Distinct ETags collide onto one blob, serving the wrong bytes

`R/utils.R:51-52`

Both `gsub` calls are global and unanchored, so every quote and every `W/` substring is stripped
wherever it appears.

```
'W/"abc123"'  → "abc123"   ┐ weak and strong collide
'"abc123"'    → "abc123"   ┘
'"aW/b"'      → "ab"          mid-string mangling
'"vW/1abc"' and '"v1abc"' → both "v1abc"   collide: TRUE
```

Whichever downloads first wins; the second request is served the first file's content.

### F7 · HIGH · [CONFIRMED] — Without symlink support the cache design inverts and re-downloads every call

`R/utils.R:141` · `R/cache_hfhub.R:178`

`link_or_copy(owned = TRUE)` *moves* the blob into the snapshot rather than copying it. The
blob-exists check is then always false, so every call re-downloads and two commits sharing an ETag
never deduplicate — on Windows without developer mode, precisely the platform the blob/snapshot split
exists to serve.

### F8 · HIGH · [CONFIRMED] — The lock serializes concurrent downloads without deduplicating them

`R/utils.R:164` · `R/cache_hfhub.R:174, 178` · `R/cache_parquet.R:152, 160`

Existence checks sit outside the lock and nothing re-checks inside it, so the second process waits and
then downloads anyway — overwriting a blob another process may already be reading through a symlink.
Two processes, same blob, 5-second server:

```
[P2] blob exists? FALSE → download → returned after  5.01s
[P1] blob exists? FALSE → download → returned after 10.11s
                          (waited 5s on the lock, then downloaded again)
```

`filelock::lock()` also defaults to `timeout = Inf` and is held across the entire network transfer, so
a stalled peer blocks every other process indefinitely with no message.

### F9 · HIGH · [CONFIRMED] — A `file_name` with a directory returns a path to a file that does not exist

`R/cache_hfhub.R:161-165, 189` · `R/utils.R:137`

Only `snapshots/<hash>` is created, and `file.symlink()`'s return value is discarded, so the failure is
a warning at most. The blob downloads, bandwidth is spent, and the caller receives a dangling path —
for a layout `design/cache-hfhub.md` explicitly documents as supported (`data/train.csv`).

### F10 · HIGH · [CONFIRMED] — `list_datasets()` returns more rows than requested

`R/list_datasets.R:92-96, 116`

The loop breaks when `fetched >= num_of_dataset` but `rbindlist(all_data)` is never truncated.
Verified against live huggingface.co:

```
list_datasets(num_of_dataset = 5, chunk_size = 2, search = "iris")  → 6 rows
list_datasets(num_of_dataset = 250, chunk_size = 100)               → 300 rows
```

Related: `gated` flips between `logical` and `character` depending on which datasets matched (HF
returns `"auto"` for some), so the column type of the public return value is not stable. The test
asserting `expect_type(…, "logical")` passes only by luck of the current trending list.

### F11 · MEDIUM · [CONFIRMED] — `refs/` is written before the download, leaving a corrupt half-state on failure

`R/cache_hfhub.R:167-172` precede `:182`

```
after a failed download:
  blobs/                                    (empty)
  refs/main            → "2f090f19d72acd…"  claims a commit
  snapshots/2f090f…/                        (empty)
```

Any correct offline resolver — once F2 is fixed — will resolve `main` to that hash and miss.

### F12 · MEDIUM · [CONFIRMED] — A branch name containing `/` permanently breaks the plain branch

`R/cache_hfhub.R:168-171`

```
revision="main" then "main/v2" → EEXIST  Failed to make directory 'refs/main'
revision="main/v2" then "main" → EISDIR  illegal operation on a directory
```

Once a user touches a slash-containing revision, that branch is uncacheable until the cache is
hand-repaired. `revision="refs/convert/parquet"` also silently produces `refs/refs/convert/parquet`.

### F13 · MEDIUM · [CONFIRMED] — `cache_parquet` reports every upstream failure as a missing config

`R/cache_parquet.R:70-97, 120-129, 147-152`

The API call has no status check, no auth headers and no retry. A gated dataset, a rate limit, a
not-yet-processed conversion and a size-limit rejection all produce the same message with an empty
list — the real cause is discarded. An HTML error page instead surfaces a raw `jsonlite` lexical
error. A 404 without `x-error-code` proceeds to download the error body, and a `NULL` etag or commit
hash yields `argument is of length zero`.

```
R> cache_parquet(repo_id = "a/b", config = "default")   # gated dataset
Error: Config 'default' not available:
```

### F14 · MEDIUM · [CONFIRMED] — The backends reject common Hub formats and produce unusable classification data

`R/backend_hfhub.R:8, 12, 14, 15`

```
t.csv.gz  → Error: currently not supporting for your given format: gz
noext     → Error: currently not supporting for your given format:
TaskClassif$new(…) → Error: Target 'g' must be a factor or ordered factor
```

`.csv.gz` is common on the Hub. `stringsAsFactors = FALSE` means no CSV-sourced dataset can be a
classification target, and `read.csv`'s default `check.names = TRUE` mangles Hub column names
(`class label` → `class.label`, `2nd col` → `X2nd.col`).

### F15 · MEDIUM · [CONFIRMED] — Split order is lost, and schema mismatches are filled with `NA` in silence

`R/backend_parquet.R:13-18, 33`

`split()` reorders alphabetically, so `train`/`test` comes back as `test`/`train`. `fill = TRUE` masks
genuine schema differences between splits with no warning. On an unnamed list the `idcol` yields
`"1"`, `"2"` rather than split names.

### F16 · MEDIUM · [CONFIRMED] — Documented return shapes and defaults do not match the code

`R/cache_parquet.R:23, 27-33, 58-64` · `R/download_desc.R:6`

Four separate contract breaks. `cache_parquet`'s `@return` promises entries of `list(split=, path=)`;
it returns bare character vectors, so `res[[1]]$split` errors. Its `@param revision` claims a `NULL`
default while the real default is `"refs%2Fconvert%2Fparquet"` — and passing `NULL` gives
`length(url) == 1 is not TRUE`. Its signature puts the required `config` *after* a defaulted
`revision`, so the natural call from the README misbinds. `download_desc`'s `...` is documented as
passed to `httr::GET` and is never referenced, which silently swallows the third positional argument.

```
R> cache_parquet("scikit-learn/iris", "default")
Error: argument "config" is missing   # "default" bound to revision
```

### F17 · LOW · [CONFIRMED] — Assorted smaller defects

- `cache_parquet.R:193` — `message("Snapshot link failed for: {curr_split}")` prints the braces
  literally, and because it is a `message()` rather than an abort, the missing path is still appended
  to the return value.
- `utils.R:219, 263` — `attempt` is incremented before `2^attempt`, so the first backoff is 4s, not
  2s; the default worst case is 12s of sleeping. `Retry-After` is ignored on 429.
- `utils.R:164` — lock files are never unlinked, including for downloads that never succeeded: one
  permanent zero-byte file per ETag ever attempted, inside `blobs/` where Python keeps only blobs.
- `utils.R:137` — symlinks are written as absolute paths, so the cache cannot be relocated; both
  design docs draw them as relative.
- `utils.R:84` — `as.integer(content-length)` returns `NA` with a user-visible coercion warning above
  2 GiB.
- `utils.R:99-120` — `supports_symlinks()` probes a fixed `.symlink_test` path; two concurrent
  processes hit ~10% failures, either an `ENOENT` that aborts the download or a spurious `FALSE`
  cached for the whole session, which flips on the destructive move behaviour in F7.

---

## Surface 03 — Packaging: a clean check that is manufactured, not earned

`R CMD check --as-cran` on a fully-provisioned machine reports only three NOTEs. That result is
produced by `globalVariables()` suppressions, an `interactive()` guard hiding a broken example, and a
CI configuration that always installs every Suggests package.

Under `_R_CHECK_DEPENDS_ONLY_=true` the check goes to **`Status: 1 ERROR`**.

### P1 · HIGH · [CONFIRMED] — The core download path calls a Suggests-only package, and nothing catches it

`R/utils.R:163` · `R/backend_hfhub.R:28` · `R/backend_parquet.R:36`

`withr::with_tempfile()` sits inside `download_file()` — used by both `cache_hfhub` and
`cache_parquet` — and `mlr3::as_data_backend()` in both backends. Both packages are in **Suggests**.
`tools` and `utils` are used via `::` and declared nowhere.

The original hypothesis was half wrong in an important way: `R CMD check` reports
`checking dependencies in R code ... OK`, because `::` to a *declared* Suggests package is permitted.
Only CRAN's written policy is violated, and no automated gate exists. On a library path with only the
declared Imports:

```
WARN: Attempt 1/1 failed: there is no package called 'withr'
Error: Download failed after 1 attempts
  <https://huggingface.co/datasets/scikit-learn/iris/resolve/main/Iris.csv>
```

Note the second failure mode: `download_file()`'s `tryCatch` swallows the `packageNotFoundError`,
retries it three times with backoff, and then tells the user the *network* failed.

### P2 · HIGH · [STATIC] — An undeclared minimum of R 4.4 via base `%||%`

`R/utils.R:81` · `DESCRIPTION` (no Depends field)

`%||%` has no definition and no import in this package; it resolves to `base::%||%`, which R's own
NEWS records as new in **R 4.4.0**. DESCRIPTION has no `Depends:` field at all, so on R 4.3 and
earlier `get_file_metadata()` dies with `could not find function "%||%"`, taking both cache functions
with it. Not executable here — no old R available — but the version claim comes from R's shipped NEWS
file.

### P3 · HIGH · [CONFIRMED] — A `download_desc` example hits the live network during `R CMD check`

`R/download_desc.R:9-11` · `man/download_desc.Rd:24-26`

Proven from the check's own artifacts — `mlr3hf-Ex.timings` shows the round trip, against 0.000 for
the three correctly-guarded examples:

```
name           user  system elapsed
cache_hfhub    0     0      0
cache_parquet  0     0      0
download_desc  0.556 0.082  0.862
list_datasets  0     0      0
```

Offline this becomes `Status: 1 ERROR`, and it makes all five CI platforms depend on huggingface.co
being reachable on every push.

### P4 · HIGH · [CONFIRMED] — CI is configured so it cannot detect the package's worst defects

`.github/workflows/R-CMD-check.yaml:42-50` · `.github/workflows/build-site.yml`

- `setup-r-dependencies` with `needs: check` installs all Suggests, so P1 is structurally invisible.
- `check-r-package` sets no `error-on:`, defaulting to `warning` — all three NOTEs pass green.
- `oldrel-1` is R 4.5, which already has `%||%`, so P2 can only surface on a user's machine.
- `list_datasets`'s only two tests carry `skip_on_ci()`, so the one exported function with NSE and
  pagination has zero CI coverage.
- `build-site.yml` depends on `secrets.*` unavailable to fork PRs, so it fails for every external
  contributor, and deploys hardcoded to a contributor's account.

### P5 · MEDIUM · [CONFIRMED] — The suite errors rather than skips when Suggests are absent

`tests/testthat/setup.R:1-2`

Unconditional `library(vcr)` / `library(webmockr)` with no `skip_if_not_installed()` anywhere. Under
`_R_CHECK_DEPENDS_ONLY_=true` the check goes to `Status: 1 ERROR`.

### P6 · MEDIUM · [CONFIRMED] — A malformed roxygen line is rendered into the user-facing help page

`R/list_datasets.R:31` · `man/list_datasets.Rd:50-54`

The doubled `#' #'` prefix makes roxygen treat the tag as prose, so `?list_datasets` and the pkgdown
site both display raw roxygen source inside `\references`:

```
\references{
\url{https://huggingface.co/docs/hub/api}

#' @importFrom data.table data.table as.data.table rbindlist
}
```

The intended import never reached NAMESPACE — harmless, since `data.table()` is never called and `.()`
needs no import. Everything else in the NAMESPACE audit is clean: all four exports have matching
usage, documented arguments and `\value`.

### P7 · MEDIUM · [CONFIRMED] — The tarball ships `.claude/` and `design/`, causing two of the three NOTEs

`.Rbuildignore`

`tar tzf` confirms `mlr3hf/.claude/settings.local.json` and `mlr3hf/design/*.md` are in the built
package. `^\.github$` and `^README\.Rmd$` are correctly excluded; `^\.claude$` and `^design$` are
missing, and the file has no trailing newline.

### P8 · MEDIUM · [CONFIRMED] — Submission metadata is incomplete and points at a fork

`DESCRIPTION` · `LICENSE` · `_pkgdown.yml`

Check NOTEs on the version (`0.0.0.9000`) and Title case. `BugReports` is absent entirely. `URL` and
`_pkgdown.yml` both point at a contributor's personal Pages site while the maintainer of record is
someone else. Toby Hocking has `cre` without `aut`, and there is no `cph` anywhere — though the
`LICENSE` file names Anjani Nandan, a `ctb`, as copyright holder. The LICENSE two-line format itself is
correct.

### P9 · LOW · [CONFIRMED] — Dependency hygiene

- `data.table` is listed twice in Imports. `R CMD check` says nothing —
  `tools:::.split_dependencies()` returns a named list, so the duplicate is silently overwritten.
- `arrow` is declared in Suggests and used nowhere (`grep` across `R/` and `tests/` returns zero
  hits). It is nonetheless the heaviest CI install and blocks a strict check outright:
  `Package suggested but not available: 'arrow'`.
- `utils::globalVariables()` is masking eight real check NOTEs. Both suppressions are load-bearing
  given the current code, but the `"tmp"` one exists only because of the `withr` dependency in P1 —
  dropping `withr` for a plain `tempfile()` removes both problems at once.
- Separately, `nanoparquet` 0.5.1 fails to install on R 4.6.1 with byte-compilation enabled. That is
  upstream's bug, but `mlr3hf` hard-Imports it, so mlr3hf is uninstallable wherever it bites.

---

## Surface 04 — Tests: seventy-five green expectations, load-bearing in about four places

Coverage is 67.66%, but line coverage is the wrong measure here. The code under test was mutated and
the tests counted by whether they noticed.

### T1 · CRITICAL · [CONFIRMED] — The cassettes are a fig leaf — four tests download real bytes every run

`test-cache_hfhub.R:19, 30` · `test-cache_parquet.R:41, 55` · `R/utils.R:199`

vcr and webmockr hook `httr`; `download_file()` uses `curl::curl_download()`, which they cannot
intercept. The cassettes cover only the `HEAD` metadata call — no cassette contains a `GET` for
`Iris.csv` or `0000.parquet`. Proof, same suite behind a dead proxy:

```
── Error ('test-cache_hfhub.R:23:5') ──────────────────────────────
Error in `download_file(...)`: Download failed after 3 attempts:
<https://huggingface.co/datasets/scikit-learn/iris/resolve/main/Iris.csv>
```

A second-order consequence: the cassette supplies a pinned commit hash and ETag while curl supplies
live bytes, so when HF re-converts the parquet branch the new bytes get cached under the stale key —
passing, and silently wrong.

### T2 · CRITICAL · [CONFIRMED] — `webmockr::enable()` is never called, so the stub is inert

`tests/testthat/setup.R:1-6` · `test-cache_parquet.R:9-28`

```
httr adapter enabled?: FALSE
N stubs registered:     1
REAL request performed? status: 200, nchar body: 283
```

The test passes only because the live datasets-server still returns exactly one split named `train`.
Its assertion message and its actual failure mode do not even match:

```
Expected match: "Splits not available: nonexistent. Available: train"
Actual message: "Couldn't connect to server [datasets-server.huggingface.co]"
```

### T3 · HIGH · [CONFIRMED] — 14 of 18 backend tests survive destroying every value read from disk

`test-backend_hfhub.R` · `test-backend_parquet.R`

Every column was constant-filled after reading, so the file readers return garbage. Six of eight
`backend_hfhub` tests and eight of ten `nano_parquet` tests still passed — and the four detections
were incidental mlr3 crashes, not assertions. The test named *"supports full pipeline + resampling
workflow"* passed with all data destroyed. Every assertion checks shape:
`inherits(x, "DataBackend")`, `$nrow`, `$primary_key`, `expect_s3_class(rr, "ResampleResult")`. None
checks a value.

### T4 · HIGH · [CONFIRMED] — Three more tests that cannot fail

`test-utils.R:45-73` · `test-download_desc.R:1-9` · `test-utils.R:96-110`

- **`get_file_metadata`** — stubbed to return an all-`NULL`, always-404 list, the suite still reported
  `utils: ............12........`. "Returns expected fields" checks only `names()`; "returns 404"
  checks only that the hardcoded 404 is 404.
- **`download_desc`** — line 8 is literally `expect_equal(x$description, x$description)`, the same
  object against itself. It passes when the function returns `NULL`.
- **`link_or_copy`** — an earlier test leaves `FALSE` cached in `symlink_support_cache` for
  `tempdir()`, so the test named for the symlink branch actually exercises `fs::file_move`. Its single
  assertion passes for a `link_or_copy` that does nothing but return its argument. The symlink branch
  has no real coverage, and this is order-dependent state leaking across files.

### T5 · HIGH · [CONFIRMED] — Two source files are at 0%, and nothing tests the thing the package is for

```
mlr3hf Coverage: 67.66%
R/download_hfhub.R    0.00%      R/download_parquet.R  0.00%
R/cache_hfhub.R      49.46%      R/list_datasets.R    63.46%
R/utils.R            81.42%      R/cache_parquet.R    82.24%
```

Zero coverage on: the `local_files_only` path, the `refs/` branch, the commit-hash early return, blob
reuse, `download_file`'s retry path, `get_with_retry`'s 429/5xx path, `list_datasets` pagination, and
the entire authenticated-request path (`hub_headers`'s authorization branch and all of
`mlr3hf_token`).

No test anywhere connects a downloaded Hub file to a Task — all three "end-to-end" tests write their
own local temp files, and `backend` never appears in either cache test file.

### T6 · MEDIUM · [CONFIRMED] — Suite configuration

`Config/testthat/edition` is absent from DESCRIPTION, so despite `testthat (>= 3.0.0)` in Suggests the
suite runs in **edition 2** — `expect_equal` uses tolerant `all.equal` rather than waldo, and
deprecation strictness is off. Adding the field changed nothing in the current results (79 passing
either way).

`test-download_desc.R:61` pins `usedStorage == 5309549` with a comment acknowledging it may change; it
is safe only because it is cassette-served, and becomes a time bomb the moment anyone re-records.

### T7 — What the test suite gets right

- **No secrets in any cassette.** vcr's httr adapter does not serialise request headers at all — every
  fixture has only `method:` and `uri:` under `request:`. This was verified prospectively by
  re-recording with a fake `HF_TOKEN` set, confirming `hub_headers()` really did send it, and finding
  zero occurrences in the resulting cassette.
- **No pollution of the real cache.** `~/.cache/huggingface` did not exist before or after eight full
  suite runs, and a cold run passes — the tests are not secretly warm-cache-dependent.
- **Three genuinely good tests.** `normalize_etag`, `repo_folder_name` and `hub_url` are properly
  value-checked, and `download_desc`'s httr-mocked 404 is a real error-path test.

---

## Surface 05 — Hypotheses that did not survive contact

These were proposed as likely defects and tested. They are not problems, and the reasoning is recorded
so nobody re-litigates them.

### R1 — Bearer token leaking through HTTP redirects

libcurl 8.5.0 strips the custom `authorization` header on every origin change — tested cross-host,
same-host-different-port, and https→http downgrade, for both `curl_download` and `httr::GET`. The sink
logged no auth in all three. Caveat: the code relies entirely on libcurl for this, nothing pins a
minimum libcurl, and pre-7.58 does forward the header. The redirect *body* is still accepted without
question.

### R2 — `on.exit` inside the retry loop accumulating locks into a deadlock

`on.exit` registers on the innermost `eval` context, not `download_file`'s frame, so the unlock fires
at the end of each iteration. A closed-port run completed three attempts in 12.42s with no hang.
`filelock` is also re-entrant within a process, so even a leaked lock would not self-deadlock. Note:
`add = TRUE` is load-bearing — a bare `on.exit()` there would clobber withr's cleanup.

### R3 — `man/` being stale relative to `R/`

Re-running roxygen produces zero diff in `man/` or `NAMESPACE`. The garbage in `\references` (P6) is
faithfully regenerated — it is a source bug, not drift.

### R4 — The two parquet code paths parsing the same endpoint incompatibly

They hit genuinely different endpoints — `/api/datasets/{id}/parquet` returns `config → split → urls`,
`datasets-server.huggingface.co/parquet` returns a `parquet_files` array — and each parses its own
correctly. The real problem is that the package carries two parallel implementations of one feature,
one of them dead.

### R5 — Five smaller hypotheses

- **Absolute `file_name` escaping the cache** — `fs::path()` drops the leading slash and joins.
- **`repo_folder_name` traversal on POSIX** — replacing `/` and `:` genuinely neutralizes it, though
  backslashes survive and would traverse on Windows.
- **`is.null(config)` being unreachable** — it is reachable via an explicit `config = NULL`; only the
  *omitted*-argument case bypasses it.
- **`all_headers` being empty without redirects** — populated correctly.
- **Cross-device `file_move` failing** — `fs::file_move` handles it, though as copy-plus-delete, so
  publishing a blob is not atomic and a concurrent reader can observe a partial file.
- **pkgdown reference coverage** — `_pkgdown.yml` has no `reference:` section, so the index
  auto-generates; `check_pkgdown()` is clean.

---

## If you fix in one order, this one

Nothing above is applied — this report is diagnosis only. But the findings are not independent, and
some fixes unblock others.

1. **Validate every path component that comes off the wire.** Constrain `etag` and `commit_hash` to a
   hex/safe-character pattern, and reject or sanitize `..` in `file_name`, `revision`, `split` and
   `filename`. This closes S1-S4, S8 and S10 at one point, and it is the only class of finding here
   that is dangerous rather than merely broken.
2. **Move `withr` and `mlr3` to Imports** — or drop `withr` for `tempfile()`, which also removes the
   `globalVariables("tmp")` suppression. Add `Depends: R (>= 4.4)` or define `%||%` locally. The
   package is currently broken on a declared-deps-only install.
3. **Fix the unbound `etag`/`url` in `cache_hfhub`** and give that test a `regexp`. Until the
   assertion is tightened, this bug is designed to stay hidden.
4. **Read all shards** in `nano_parquet`, and use the API-supplied `url` in `cache_parquet` instead of
   rebuilding it. These are the two silent-wrong-data findings.
5. **Decide what the package's public API is.** Either export a Task or backend constructor, or change
   the Title and README to describe what it does — cache files from the Hub. Right now the two
   disagree.
6. **Then make the tests load-bearing:** assert values rather than shapes, stub at the `curl` layer or
   inject the downloader so the cassettes actually isolate, call `webmockr::enable()`, and add
   timeouts to every request.

---

## Method and limits

Seven agents worked in parallel over four attack surfaces: filesystem/path safety, network and
credential handling, cache control flow, concurrency and backends, R CMD check and CRAN compliance,
test-suite integrity, and public API/documentation. Findings marked CONFIRMED were reproduced by
execution against R 4.6.1, using local HTTP servers on 127.0.0.1 with a fake token, a sandboxed cache
directory, and a scratch copy of the repository. A small number of read-only unauthenticated requests
were made to huggingface.co to verify real API response shapes.

**Limits.** `arrow` could not be installed, so a fully strict `R CMD check` was not run; `nanoparquet`
needed `--no-byte-compile`. R < 4.4 was unavailable, so P2 is argued from R's NEWS rather than
executed. Windows path semantics were not tested. Two sub-findings (the file-placement half of S10,
and `download_parquet`'s traversal) are static-only and marked as such.
