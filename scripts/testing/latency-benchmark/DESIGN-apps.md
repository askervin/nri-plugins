# Design: more than one application under the same ladder

The harness measures one application, `sleep-accuracy`, and its whole
record is shaped like that application's output: 23 CSV columns copied
from the tool, a validity gate that reads the tool's `schedpol` field, a
`pgrep -x sleep-accuracy`, and one Job template. This document designs
the change that lets the same stage ladder measure **compute-intensive
`openssl`** and **latency-sensitive `redis`** as well, without giving up
anything the sleep-accuracy campaigns already rely on.

Two sources define what the new applications should do:
[the PCT quick start](../../../docs/resource-policy/policy/howto/balloons-pct-quickstart.md),
which measures `openssl speed -evp aes-128-cbc` in an HP pod against a
plain one, and Intel's
[optimization-zone quick start](https://github.com/intel/optimization-zone/blob/main/software/kubernetes/nri-resource-policies/quickstart.md),
which measures `redis-benchmark -n 200000 -c 50 -t get` against a
dedicated balloon and a shared one.

## The one invariant that makes this cheap

**Every application runs in the same balloon, with the same pod label,
requesting the same CPUs.** `BENCH_LABEL_KEY`/`BENCH_LABEL_VALUE`,
`BENCH_CPUS`, `BENCH_CPU_REQUEST` and `BENCH_MEM_REQUEST` stay shared and
application-independent.

That is not tidiness, it is what keeps the ladder meaningful: the stage
functions in `stages.sh` describe a balloon, and if each application
brought its own balloon shape then a difference between two applications
would be partly a difference in what the policy was asked to do. With the
invariant, **`stages.sh` and `gen-balloons-config.sh` need no change at
all** for openssl, and one additive change for redis (below). The eight
stages configure exactly what they configure today, and the application
is a different way of observing the same node.

## Parameterisation: one variable, one option

```sh
BENCH_APPS="sleep-accuracy"                  # the default: today's behaviour
BENCH_APPS="openssl"
BENCH_APPS="sleep-accuracy,openssl,redis"    # all three, per stage, in order
```

and, so it is discoverable from `-h`:

```sh
./run-benchmark.sh -a openssl,redis
./run-benchmark.sh -a openssl realtime-sched pct-priority-cores
```

Applications run **sequentially inside a stage**, never concurrently. Run
together they would contend for the balloon's CPUs and none of them would
be measuring the policy. Run in sequence they see the same node state,
the same policy generation and the same instance of the background load,
which is stronger evidence than three separate campaigns can give — at
the cost of multiplying stage wall-clock by the number of applications.
`APP_SETTLE_SECONDS` (default 5) separates them.

Per-application knobs use the application's own name as prefix,
uppercased with `-` becoming `_`. `SLEEP_ACCURACY_IMAGE` already follows
this convention, so nothing has to be renamed:

| variable | default | meaning |
| --- | --- | --- |
| `SLEEP_ACCURACY_IMAGE` | `localhost/sleep-accuracy:latest` | as today |
| `SLEEP_ACCURACY_ARGS` | as `BENCH_ARGS` is built today | `BENCH_ARGS` stays a documented alias |
| `OPENSSL_IMAGE` | `localhost/openssl:latest` | built by `build-images.sh -o` |
| `OPENSSL_CIPHER` | `aes-128-cbc` | passed to `speed -evp` |
| `OPENSSL_SECONDS` | `5` | per block size, per round |
| `OPENSSL_MULTI` | unset (one thread) | `-multi N`; see below |
| `OPENSSL_ROUNDS` | `3` | invocations, to match `BENCH_REPEATS` |
| `REDIS_IMAGE` | `docker.io/library/redis:7-alpine` | server and client |
| `REDIS_CLIENT_ARGS` | `-n 200000 -c 50 -t get` | the load generator |
| `REDIS_ROUNDS` | `3` | invocations |
| `REDIS_CLIENT_CPUS` | `2` | the client's own balloon |
| `REDIS_HOST_NETWORK` | unset | loopback instead of the pod network |

Nothing else in the environment changes meaning. `NOISE_*`,
`RESULTS_DIR`, `STAGE_RETRIES`, `SKIP_DURING_VALIDATION` and the
`OVERRIDE_*` forwarding are untouched.

## Application modules

A new directory, sourced the way `stages.sh` is:

```
apps.sh                        sources every apps/*.sh
apps/sleep-accuracy.sh         apps/sleep-accuracy.yaml.in
apps/openssl.sh                apps/openssl.yaml.in
apps/redis.sh                  apps/redis.yaml.in   apps/redis-client.yaml.in
```

`sleep-accuracy-job.yaml.in` moves to `apps/sleep-accuracy.yaml.in`
unchanged. Each module defines five functions by naming convention, and
`declare -F app_${name}_manifest` is what decides whether an application
exists — the same dispatch `declare -F stage_$name` already uses, so no
registry and no new machinery:

```sh
app_<name>_defaults()   # fill in APP_* for this application
app_<name>_manifest()   # print the Job/Deployment yaml on stdout
app_<name>_start()      # optional: bring up anything the Job needs first
app_<name>_metrics()    # raw log -> canonical metric rows on stdout
app_<name>_witness()    # optional: what the app's own output proves
```

`app_<name>_defaults` sets the variables the harness needs to supervise
any application, which is the whole of what the harness has to know:

```sh
APP_LOG=openssl.log            # raw output, kept in the stage directory
APP_JOB_NAME=openssl           # the Job to wait for
APP_POD_SELECTOR=app=openssl   # how to find its pod
APP_SUBJECT_POD=openssl        # whose cgroup is "the benchmark's cpuset"
APP_SUBJECT_PROCESS=openssl    # what pgrep -x should find
APP_TIMEOUT=$BENCH_TIMEOUT
```

For redis the subject is the **server**, not the client: the server is
what sits in the balloon under test, so the server's cpuset, cgroup and
scheduling policy are what every state check must be about.

## The canonical metrics record

The three applications measure genuinely different things — a wakeup
latency distribution in nanoseconds, a cipher throughput in bytes per
second, a request latency in milliseconds plus a request rate — so a
single wide row with fixed columns cannot hold them. Each application
therefore emits long-form rows with nine columns, appended to the
existing 26 configuration and 2 verification columns exactly as
`csv_append_stage` composes a row today:

| column | meaning | sleep-accuracy | openssl | redis |
| --- | --- | --- | --- | --- |
| `app` | which application | `sleep-accuracy` | `openssl` | `redis` |
| `benchmark` | its own sub-benchmark | `nanosleep` | `aes-128-cbc` | `get` |
| `round` | repetition within the stage | `-r` round | invocation | invocation |
| `op` | the operating point, numeric | `1000` | `16384` | `50` |
| `op_unit` | what `op` counts | `sleep_ns` | `block_bytes` | `clients` |
| `metric` | what is measured | `p50`, `p99`, … | `throughput`, `ns_per_op` | `p99`, `rps`, `ns_per_request` |
| `unit` | of `value` | `ns` | `bytes_per_s`, `ns` | `ns`, `ops_per_s` |
| `better` | `lower` or `higher` | `lower` | `higher` / `lower` | `lower` / `higher` |
| `value` | the number | | | |

Per stage: `metrics.csv`. Per run: `metrics.csv`, the concatenation with
the configuration and verification prefix, which is the file the plot
pipeline consumes.

`op` and `op_unit` are two columns rather than one because the plot
script has to label panel rows per application — "sleep 1 µs", "16 KB
blocks", "50 clients" — and a bare number cannot be labelled.

### `latencies.csv` does not change

When `sleep-accuracy` is among the applications, the run still gets a
`latencies.csv` with exactly today's 51 columns and rows, written by
exactly today's awk. That is deliberate duplication in one function, and
it buys two things: the 30 archived v1 cycles keep their tooling and
their checksums, and a new sleep-accuracy campaign stays directly
comparable to them by the scripts that already exist. Applications other
than sleep-accuracy contribute no rows to it.

A converter, `latencies-to-metrics.py`, turns an archived `latencies.csv`
into canonical metric rows, so the v1 series plots through the new
pipeline without being re-measured.

## openssl

Run as a Job like sleep-accuracy, not through `kubectl exec` into an idle
pod as the quick start does. The Job's container is the thing that
lands in a balloon, it is created after the plugin is serving NRI, and
the existing `bench-not-assigned` and cpuset checks work on it unchanged.
An `exec` into a pre-existing pod would sidestep all of that.

A small image built beside the others (`build-images.sh -o`, fedora
-minimal plus `openssl`), so there is no registry and no pull, matching
`imagePullPolicy: Never`.

Args, repeated `OPENSSL_ROUNDS` times by a one-line shell wrapper that
prints `=== round N` between invocations:

```sh
openssl speed -seconds "$OPENSSL_SECONDS" -evp "$OPENSSL_CIPHER"
```

**Single-threaded by default.** `-multi` is not passed unless
`OPENSSL_MULTI` is set. That keeps the single-thread premise the
sleep-accuracy campaigns rest on: with one thread and a two-CPU cpuset
the only thing the second CPU changes is whether the scheduler may
migrate, which is the comparison the `1cpu`/`2cpu` campaign pairs exist
to make. `OPENSSL_MULTI=$BENCH_CPUS` is the throughput-maximising
alternative and is a different experiment.

Parsing is the `type`/cipher table:

```text
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
AES-128-CBC    1788838.33k  2156328.92k  2205063.68k  2217644.85k  2221249.33k  2221617.97k
```

One row per block size, twice:

```
openssl,aes-128-cbc,1,16384,block_bytes,throughput,bytes_per_s,higher,2221617970
openssl,aes-128-cbc,1,16384,block_bytes,ns_per_op,ns,lower,7375
```

The `k` suffix is 1000 bytes/s and is resolved so the unit column is
honest. Why also emit `ns_per_op`: see the axis-direction problem below.

For a throughput figure the interesting tail is not a percentile — there
is none — but the **spread across rounds and the worst round**, which the
plot script's existing `--rounds min|all` already expresses.

## redis

Three moving parts, and the one design question that matters is where
the load generator runs.

- **Server** — a Deployment in the balloon under test, carrying
  `BENCH_LABEL_KEY=BENCH_LABEL_VALUE` like every other subject, so every
  stage treats it exactly as it treats sleep-accuracy today. Started with
  `--save "" --appendonly no --protected-mode no`: a background save
  forks the server and writes to disk, and that would land in precisely
  the tail latencies being measured.
- **Client** — a Job running `redis-benchmark` `REDIS_ROUNDS` times.
- **Client placement** — in **its own dedicated balloon**, not in the
  noise and not in the default balloon.

The client placement is not a detail. A measured round trip is client
wakeup plus loopback plus server work plus server wakeup, so an
unprotected client under 90 replicas of stress-ng contributes its own
delay to every stage equally badly, and the ladder flattens into a false
negative. Worse, in stage 7 a client in the `other` cpuClass would be
capped at base frequency, so the stage would look like a regression
caused by its own instrument.

So the harness gives the client a fixed balloon that **no stage
configures**: `REDIS_CLIENT_CPUS` dedicated CPUs, no cpuClass, no
scheduling class, identical in all eight stages. That requires one
additive change to `gen-balloons-config.sh` — a `CLIENT_*` role beside
the existing `BENCH_*`, `NOISE_*` and `DEFAULT_*` — emitted only when an
application declares it needs a client. `stages.sh` still needs no
change, and the client's stage-independence is exactly the property that
lets a change in p99 be attributed to the server's configuration.

The consequence to write down rather than hide: stage 7's "every other
class capped at base" is no longer literally true of the whole node,
because the client is deliberately exempt. The client is measurement
apparatus, not workload.

Connection: the client gets the server's pod IP via
`kubectl get pod -o jsonpath='{.status.podIP}'`, which avoids a Service
hop and one more moving part. `REDIS_HOST_NETWORK=1` switches both to
host networking and `127.0.0.1`, which removes CNI variability at the
cost of being less representative. Either way the network path is a
constant added to every stage, so the ladder's differences survive it.

Parsing the `redis-benchmark` summary:

```text
Summary:
  throughput summary: 108108.11 requests per second
  latency summary (msec):
          avg       min       p50       p95       p99       max
        0.311     0.088     0.303     0.415     0.559     1.303
```

becomes, with `op=50` (`-c`) and `op_unit=clients`:

```
redis,get,1,50,clients,p99,ns,lower,559000
redis,get,1,50,clients,rps,ops_per_s,higher,108108
redis,get,1,50,clients,ns_per_request,ns,lower,9250
```

Latencies are converted to nanoseconds so they share a unit and a log
axis with sleep-accuracy. The source resolution is one microsecond —
`redis-benchmark` prints three decimals of a millisecond — so every
value is an exact multiple of 1000 ns. That has to be stated in the
campaign notes, or someone will read the quantisation as jitter.
`memtier_benchmark` would give real percentiles and its own pinning;
`REDIS_CLIENT_ARGS` is a variable so it can be dropped in later without
touching the module.

## Keeping the validity gates as strong as they are

This is where a generalisation quietly degrades a harness, so each
existing check gets a named replacement rather than a fallthrough.

| check today | how it generalises |
| --- | --- |
| `capture_cgroups -p $BENCH_JOB_NAME` | `-p $APP_SUBJECT_POD`. For redis the subject lives for the whole stage, so the poll that races a short benchmark wins on the first read. |
| `pgrep -x sleep-accuracy` | `pgrep -x "$APP_SUBJECT_PROCESS"` (`openssl`, `redis-server`). |
| `check_stage_measured_config` reading sleep-accuracy field 6 for `schedpol` | Becomes `app_<name>_witness`, which sleep-accuracy implements with today's awk. Applications without one fall back to the **outside** view: `bench_process_snapshot` already records `chrt -p` per task in `bench-process-during.txt`, so a stage that set `BENCH_SCHEDULINGCLASS` and finds no `SCHED_FIFO` there measured the baseline. That reuses evidence already being collected and is a stronger witness than the tool's self-report. |
| `csv_append_stage` on `NF == 23` and `nanosleep\|networking\|futex` | Per-application `app_<name>_metrics`. sleep-accuracy's keeps the identical awk for `latencies.csv`. |
| `measurements=0` | Row count in the stage's `metrics.csv`, per application. |
| `STAGE_ARTIFACTS` naming `sleep-accuracy.log` etc. | Per-application entries `<app>.log`, `<app>-job.yaml`, `<app>-pod.yaml`, generated by looping `stage_expected_artifacts` over `$BENCH_APPS`. `metrics.csv` becomes unconditional. |

One combination must be **refused** rather than degraded:
`SKIP_DURING_VALIDATION` with an application that has no witness of its
own. Without the during-snapshot there is no `chrt -p` reading, so a
realtime stage would have nothing at all proving it was realtime — which
is the case the reliability rule exists to prevent. The harness errors
out at preflight instead of producing unverifiable rows.

## Plotting

The tidy step gets simpler, because `metrics.csv` is already long-form:
`prep-plot-data.py` stops melting percentile columns and only filters and
derives. Its output schema:

```
combo,campaign,app,noise,bench_cpus,cycle,stage_index,stage,round,
benchmark,op,op_unit,metric,unit,better,value
```

Campaign names gain the application, so `CAMPAIGN_RE` becomes
`^(?P<series>[^-]+)-(?P<app>[a-z0-9-]+?)-(?P<cpus>\d+)cpu-noise-(?P<noise>.+)$`
and matches `v2-redis-1cpu-noise-cpumem`. The v1 names have no app field;
the converter fills `app=sleep-accuracy`.

`plot-latencies.py` changes, smallest first:

- `--sleep` becomes `--op`, keeping `--sleep` as an alias since that is
  what the operating point means for sleep-accuracy. Panel rows are one
  per `op`, as today, labelled through `op_unit`.
- `--percentiles` becomes `--metrics`, alias kept. Defaults per
  application: sleep-accuracy `p50,p99,p999`; redis `p50,p99`; openssl
  `ns_per_op`.
- `--combos` gains the application: `sleep-accuracy/cpumem/1cpu`.
  `parse_combo` learns the extra field and keeps every existing spelling
  working for single-application data.
- `--ylim-scope global` becomes global **within one `(metric family,
  unit)`**. Nanoseconds and bytes per second cannot share a range, and
  silently letting them would produce two figures that look comparable
  and are not.
- The companion `*-table.csv` gains `metric` and `unit` columns.

### The axis-direction problem, and why `ns_per_op` exists

The reading the figures are built around is "a working ladder descends
from the upper left to the lower right". That holds only for
lower-is-better metrics. Throughput inverts it, and an inverted y axis to
compensate is a well-known way to get a chart misread.

So the harness emits the reciprocal alongside the raw figure —
`ns_per_op` for openssl, `ns_per_request` for redis — and those are what
the default figures plot: genuinely lower-is-better, in nanoseconds, on
the same log axis as every latency in the archive. The descending
staircase then means the same thing in all three applications, and an
overlay can legitimately put openssl's `ns_per_op` beside redis's `p99`.
`--metrics throughput` still gives the raw bytes-per-second figure, on
its own axis, with the direction stated in the subtitle.

### In the data store

`bin/aggregate.sh` gains a second walk producing
`analysis/all-metrics.csv` from each run's `metrics.csv`, alongside the
`all-latencies.csv` it writes today. `bin/checksums.sh` records
`metrics.csv` as well — an unrecorded measurement file is an unprotected
one. `bin/make-plots.sh` grows a per-application figure set.

## What this costs, and the series question

The default `BENCH_APPS=sleep-accuracy` produces the same measurement
from the same image with the same arguments against the same policy
configurations. What changes is that a template moved, `metrics.csv`
appears, and `ARTIFACTS.txt` lists different names.

It can be argued that none of that touches the measurement path. The
reliability rule says otherwise — a changed script is a reason to restart
— and the rule should win, because the argument is exactly the kind that
is easy to make and hard to verify. So the first thing to run on the new
harness is a **v2 sleep-accuracy baseline**, the six existing
noise/core-count combinations, five cycles each. That both honours the
rule and gives the openssl and redis campaigns something measured by the
same harness to be compared against; a v2 that matches v1 is also the
cheapest possible evidence that the generalisation changed nothing.

A campaign remains one application, one noise class, one core count, five
cycles: `v2-<app>-<n>cpu-noise-<noise>`. `BENCH_APPS` with several
applications is for the case where three views of one node state are
wanted, not for building the comparable set.

---

# As built

Implemented 2026-08-19/20 and verified on node `pct` before any campaign ran.
Where the implementation departs from the design above, this section is
authoritative.

## Departures from the design

- **`ns_per_request` became `ns_per_op`.** redis and openssl now use one name
  for the same idea — the time one unit of work took — so a cross-application
  overlay is possible on a single metric. "op" in the metric name means one
  unit of work; the `op` column is the operating point. Two meanings of a short
  word, kept because renaming the column would have churned more than it
  clarified.
- **Per-application artifact names.** Every file an application produces is
  `<app>-<suffix>`: `<app>.log`, `<app>-job.yaml`, `<app>-pod.yaml`,
  `<app>-cgroup.txt`, `<app>-run.sh`, `<app>-verify-row.csv`,
  `<app>-node-state-during.txt`, `<app>-bench-process-during.txt`. Uniform, no
  special case for the single-application run. The first three happen to keep
  the names they had. `node-state-{before,after}.txt`, `cgroups.txt`,
  `pods.txt`, `reset.log` and the policy artifacts stay stage-wide, because
  that is what they describe.
- **`verify-row.csv` became per application.** The subject cpuset and the
  during-phase verdict belong to the application; the after-phase verdict is
  the stage's and is shared. That is more correct than the single row it
  replaces, not just a generalisation.
- **`wait_for_app_pod`** was not in the design and had to be. The
  during-validation used to sample the Job pod's phase once, immediately after
  the subject's cgroup had been polled for — right when those are the same pod,
  wrong for redis, whose subject is a long-lived server readable at once while
  the client pod is still `Pending`. Every redis stage was discarded for having
  no witness until the harness waited. Waiting was the fix; relaxing the
  witness would not have been.
- **`--ylim-scope global` is scoped to unit *and* application**, not unit
  alone. All sleep-accuracy nanosecond figures share one axis, all openssl
  `ns_per_op` figures share another. An overlay spanning applications gets the
  union, and prints the range so it can be pinned.
- **`--apps` was added** as a shorthand for "every combo of this application",
  which is what nearly every invocation wants.
- **`bin/summarize-v1.py` became `bin/summarize-ladder.py`**, one section per
  application, and `analysis/v1-plot-data.csv` became `analysis/plot-data.csv`
  since it now holds more than v1.

## The template quoting rule, learned the hard way

**Every literal double quote in a `*.yaml.in` must be written `\"`.**
`instantiate()` expands the file inside a double-quoted `eval`, so a bare quote
closes that string. Two failures came from this in one run:

- `- "no"` in the redis server args lost its quotes, YAML 1.1 read `no` as the
  boolean `false`, and the API server rejected the Deployment.
- `- "echo $B64 | base64 -d | /bin/sh"` in the openssl Job rendered an empty
  manifest *and* ran the round loop as a pipeline on the harness host.

`run_app` now refuses an empty manifest and names this as the likely cause,
which turns a silent "measured nothing" into a diagnosis.

## Other things the node taught us

- **`build-images.sh` forwards the proxy environment into the build.** Neither
  docker nor podman passes the invoking shell's `HTTP_PROXY` into a `RUN` step,
  so on this node `microdnf` hung with no output and no error until something
  timed out. Passed as build args, which are predefined for exactly these
  variables, so an unproxied node is unaffected.
- **`csv_metrics_summary` avoids gawk.** Arrays of arrays and `asort()` are
  gawk extensions; the awk on a stock Ubuntu node has neither. Sorting and
  grouping are done with `sort(1)` instead.
- **`check-comparable.sh` tests during-snapshots file by file.** `ls a b` exits
  non-zero when either is missing, so one `ls` of both the prefixed and
  unprefixed patterns reported every v2 stage as unvalidated.

## Verified before any campaign ran

`campaigns/v2-verify-2cpu-noise-none` in the data store, `SERIES=verify` so no
analysis picks it up. All three applications in one stage, four representative
stages, unloaded node, short parameters. 320 figures; every stage's
before/during/after validation present; every per-application `verify-row.csv`
reading `1-2,ok`; no stage discarded. The whole chain was then exercised on it:
`collect-v2.sh` → `aggregate.sh -f metrics.csv` → `prep-plot-data.py` →
`plot-latencies.py`, and the v1 melt through the new schema reproduced the old
figures' y range exactly (597 .. 5945144 ns), which is the regression check
that the schema change lost nothing.

## The v2 campaign set

`bin/run-campaigns-v2.sh` in the data store, copied to the node and run there.
Eighteen campaigns: {sleep-accuracy, openssl, redis} x {cpumem, vector, none}
noise x {1, 2} CPUs, one cycle each, the full eight-stage ladder. Everything
else held at v1's values — same node, same plugin image
(`nri-resource-policy-balloons:irqlog2`), same stress-ng arguments, same
reserved CPUs and disabled C-states — so a v2 sleep-accuracy campaign is
directly comparable to its v1 twin, and that comparison is also the cheapest
evidence that generalising the harness changed nothing.
