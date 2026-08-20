# Latency benchmark for the balloons policy

Measures how much the NRI balloons policy helps latency-sensitive and
realtime workloads. The emphasis is on tail latencies (P90, P99, P999)
and variance rather than averages.

The harness runs an application in a container through a ladder of
balloons policy configurations, starting from no policy at all and
adding one tuning mechanism per stage. Every stage runs against the
same background load, so the stages are comparable.

## Applications

`BENCH_APPS` selects what is measured, and `-a` does the same from the
command line:

| application | what it measures | direction |
| --- | --- | --- |
| `sleep-accuracy` | process wakeup latency from `nanosleep`, as a distribution per requested sleep length. The default and the reference. | lower is better |
| `openssl` | cipher throughput, `openssl speed -evp`, per block size. Pure CPU work, no I/O. | higher is better, and the reciprocal `ns_per_op` is emitted too |
| `redis` | request latency and rate, `redis-benchmark` against a server in the balloon under test. | lower is better |

```sh
./run-benchmark.sh                       # sleep-accuracy, the default
./run-benchmark.sh -a openssl
./run-benchmark.sh -a redis realtime-sched
BENCH_APPS=sleep-accuracy,openssl,redis ./run-benchmark.sh
```

Applications listed together run **sequentially within each stage**,
never concurrently: run together they would contend for the balloon's
CPUs and none of them would be measuring the policy. In sequence each
one sees the same node state, the same policy generation and the same
instance of the background load, which is stronger evidence about that
one stage than three separate campaigns give — at the cost of
multiplying stage wall-clock by the number of applications. A campaign
is still one application, because a campaign is the unit of comparison.

Every application runs in the **same balloon, with the same pod label,
requesting the same CPUs** (`BENCH_CPUS`, `BENCH_LABEL_KEY`,
`BENCH_LABEL_VALUE`). That is not tidiness: the stage functions in
`stages.sh` describe a balloon, and if each application brought its own
balloon shape then a difference between two applications would be
partly a difference in what the policy was asked to do. It is also why
`stages.sh` needs no application-specific knowledge at all.

An application lives in `apps/<name>.sh` plus its manifest templates,
and is found by naming convention — `declare -F app_<name>_manifest` —
the same dispatch `stages.sh` uses for stages. `DESIGN-apps.md` is the
design; `apps/redis.sh` is the one worth reading first, because its
load generator raises the only question in this that is not mechanical.

## The measurement never tunes anything itself

`sleep-accuracy` can set CPU frequencies, C-states, CPU affinity and
scheduling policies by itself, but this harness deliberately does not
let it: it runs the tool without `-p`, `-c`, `-f` and `-i`. Each of
those options configures nothing when it is not given, so everything
that affects latency is left to the container runtime and the balloons
policy, which is exactly what the benchmark is trying to measure.

The same rule applies to the other two. `openssl` is run without
`-multi`, so it is one thread and the size of the cpuset only decides
whether the scheduler may migrate it — the premise the one-core against
two-core campaign pairs rest on. `OPENSSL_MULTI` is available and is a
different experiment, not a better default.

Without `-p` the tool does not call `sched_setscheduler()` at all, and
reports the policy and priority it inherited in the `schedpol` and
`schedprio` output columns. If it did set its own policy, it would
silently erase the realtime class the balloons policy had applied and
stages 4-8 would measure nothing.

## Scripts

| Script | Purpose |
| --- | --- |
| `build-images.sh` | Builds the `sleep-accuracy`, `stress-ng` and `openssl` images and imports them into containerd's `k8s.io` namespace, and pulls the `redis` image into it. Run once. |
| `run-benchmark.sh` | The orchestrator: runs the stage ladder and collects results. This is the entry point. |
| `apps.sh`, `apps/` | The applications the ladder can measure, one module each. |
| `gen-balloons-config.sh` | Generates a `BalloonsPolicy` from environment variables. Every field is optional; an unset variable omits the field. |
| `stages.sh` | Defines the stage ladder. Each stage is a function that sets the variables `gen-balloons-config.sh` reads. |
| `reset-node.sh` | Returns the node to a known, untuned state between stages. |
| `report.sh` | Builds the CSVs and the summary tables. Also usable stand-alone. |

The `*.yaml.in` files are templates instantiated the same way the e2e
tests do it: `${VAR:-default}` and `$(...)` expanded through `eval`.

**Every literal double quote in a template must be written `\"`.**
`instantiate()` expands the file inside a double-quoted `eval`, so a bare
quote closes that string: the rest of the line then runs as a shell
pipeline on the harness host and the manifest renders empty or, worse,
renders with its quoting silently dropped. That is not hypothetical — it
is how `- "no"` first reached the API server as the YAML boolean `false`,
and how an entrypoint intended for a container first ran on the node.
`run_app` now refuses an empty manifest and names this as the likely
cause.

The configuration generator is a script rather than a `.yaml.in`
template because `cpuClasses` needs nested loops over three class
prefixes, and the `$(...)`-inside-`$(...)` quoting that would require in
a template is not maintainable.

A container entrypoint that needs a loop is carried through its template
as base64 for the same reason, and the readable script is written into
the stage directory as `<app>-run.sh` so the record still says what ran.

## Usage

On the Kubernetes node under test, as a user who can `sudo`:

```sh
./build-images.sh        # once: builds three images and pulls one
./run-benchmark.sh       # all stages, sleep-accuracy
```

```sh
./run-benchmark.sh -l                                  # list stages
./run-benchmark.sh -d                                  # dry run: print configurations only
./run-benchmark.sh baseline-no-balloons realtime-sched  # selected stages
./run-benchmark.sh -a openssl                          # a different application
BENCH_ITERATIONS=100000 BENCH_REPEATS=5 ./run-benchmark.sh
```

Per stage the script resets the node, generates and applies the
`BalloonsPolicy`, starts the background load, then runs each selected
application in turn and appends its figures to the CSVs. `-k` leaves the
last stage running for inspection instead of cleaning up.

## Stage ladder

Stages 1-7 are incremental: each keeps what the previous one configured
and adds one mechanism. **Stage 8 is a replacement**, not an increment:
it drops the cpufreq and `turboPriority` arbitration of stages 6-7 and
lets PCT hardware do the priority work instead. IRQ isolation is not a
frequency control, so stage 8 keeps it.

| # | Stage | Adds |
| --- | --- | --- |
| 1 | `baseline-no-balloons` | Nothing. No policy installed at all. |
| 2 | `default-balloon` | Policy installed, benchmark shares the default balloon with the noise. |
| 3 | `dedicated-cpus` | Own balloon with dedicated CPUs (`preferNewBalloons`). |
| 4 | `realtime-sched` | `SCHED_FIFO` priority 80 via `schedulingClasses`. |
| 5 | `isolate-irqs` | `irqMode: isolate` keeping hardware interrupts off the benchmark's CPUs. |
| 6 | `disabled-cstates` | `disabledCstates: [C1E, C6]` on the benchmark's CPUs via `cpuClasses`. |
| 7 | `max-freq-turbo-prio` | `minFreq: base`, `maxFreq: turbo`, and `turboPriority` capping every other class at base. |
| 8 | `pct-priority-cores` | `pctPriority: high` on the benchmark's CPUs, `low` everywhere else. Replaces the stage 6-7 frequency controls. |

Stage 5 also makes the noise and default balloons IRQ sinks
(`irqMode: sink`). `isolate` alone only removes the benchmark's CPUs
from an IRQ's affinity when some other allowed CPU is left, so without a
sink, IRQs whose affinity is a subset of those CPUs would stay put. The
sink gives them the noise CPUs to land on instead.

Not every IRQ can be moved. The kernel manages the affinity of some
interrupts itself and refuses to hand it over, in either of two ways:
`smp_affinity_list` is read-only, as for the per-queue MSI-X interrupts
of virtio devices, or the file is writable but every write fails with
`EIO`, as for the per-queue interrupts of NVMe and QAT devices. The
second kind cannot be spotted from the file mode, so a stage can only
discover it by trying. If such an IRQ sits on a CPU the stage isolates,
the isolation is incomplete. The harness counts the refusals into
`irq_affinity_failures` in the stage environment and marks each affinity
`rw` or `ro` in `node-state.txt`, so that this shows up as a recorded
fact rather than as unexplained latency.

A large `irq_affinity_failures` is normal on a server with many NVMe
devices and says little on its own: the drivers spread one queue per
CPU, so on a 128-CPU node every CPU hosts managed interrupts and no
choice of benchmark CPUs avoids them. What matters is whether those
interrupts actually fire. They only do when something drives the device,
and the background load here is CPU, cache and anonymous memory with no
disk I/O, so in practice they stay near-silent: measured on a 128-CPU
two-socket node, the managed NVMe queues pinned to the benchmark's CPUs
fired twice in 40 seconds under the benchmark's own load, against about
1300 per second when `stress-ng --hdd` was added. Adding disk or
accelerator load to the noise would put that interference back, and no
IRQ configuration could remove it.

Stage 8 needs a low-priority class covering everything else, including
`idleCPUClass`: idle CPUs left outside the LP CLOS would inflate the
active high-priority core count and defeat the point.

## Background load

Every stage runs the same `stress-ng` load, so that a stage's numbers
reflect the policy and not a quiet machine. `NOISE_WORKLOAD` selects
what it burns: `cpu`, `mem` (memory bandwidth), `both` (default),
`vector`, or `none`. `NOISE_REPLICAS` sets how many containers burn it
(default: half the node's CPUs).

`vector` is a different kind of neighbour from the others. Wide vector
instructions draw enough current that the core cannot hold its frequency,
and the licence-based downclocking that follows reaches every core in the
frequency domain — including one running nothing but a latency-sensitive
task that issues no vector instructions at all. It is therefore the load
that most directly tests whether the policy's frequency and priority
controls protect such a task, and the one thing a CPU and memory
bandwidth load does not exercise.

Which stressor actually costs frequency has to be measured, not assumed:
it depends on the silicon and on what the `stress-ng` build emits.
Measured on a Xeon 6776P at one instance per CPU and ~99.8% busy, the
busy frequency was 2198 MHz for `vecwide`, 2300 for `vecfp`, 2396 for
`matrix-3d`, and 2444 MHz for `vecmath`, `fma`, `matrix` and the default
`both` load — so on that part `vecmath` and `matrix` downclock no more
than plain integer work, and `vecwide` is the only clearly
licence-limited load. Hence `vector` is `--vecwide`. Check
`turbostat`'s `Bzy_MHz` at equal `Busy%` before trusting a vector
campaign on different hardware.

Comparing a `vector` campaign against a `both` campaign is only
meaningful if nothing else changed between them, since the stages differ
in how much they can do about frequency.

## Results

`RESULTS_DIR` (default `results/<timestamp>`) gets one directory per
stage with the full logs: the generated `BalloonsPolicy`, the rendered
manifests, the helm values and install log, the plugin's own log,
`kubectl` output, the node state, the stage's environment, and each
application's raw output. `ARTIFACTS.txt` in every stage directory lists
what was expected and what is there, so a thin stage is visible rather
than discovered halfway through an analysis.

Two CSVs, and the difference matters:

**`metrics.csv`** is the canonical record and the one to analyse. Every
application writes it, in long form: the 26 configuration columns, 2
verification columns, then

| column | meaning | sleep-accuracy | openssl | redis |
| --- | --- | --- | --- | --- |
| `app` | which application | `sleep-accuracy` | `openssl` | `redis` |
| `benchmark` | its own sub-benchmark | `nanosleep` | `aes-128-cbc` | `get` |
| `round` | repetition within the stage | | | |
| `op` | the operating point | `1000` | `16384` | `50` |
| `op_unit` | what `op` counts | `sleep_ns` | `block_bytes` | `clients` |
| `metric` | what is measured | `p50`, `p99`, … | `throughput`, `ns_per_op` | `p99`, `rps`, `ns_per_op` |
| `unit` | of `value` | `ns` | `bytes_per_s`, `ns` | `ns`, `ops_per_s` |
| `better` | `lower` or `higher` | `lower` | both | both |
| `value` | the number | | | |

Three applications measuring incompatible things cannot share a fixed
set of wide columns, and these nine hold any of them. `op` and `op_unit`
are two columns rather than one because a plot has to label its panel
rows per application — "sleep 1 µs", "16 KB blocks", "50 clients" — and
a bare number cannot be labelled.

Every throughput figure is accompanied by its reciprocal, `ns_per_op` —
the time one unit of work took. That is not redundancy. The reading the
figures are built around is "a working ladder descends from the upper
left to the lower right", which holds only for a lower-is-better metric,
and an inverted y axis to compensate is a known way to get a chart
misread. With `ns_per_op` the descending staircase means the same thing
in all three applications, in nanoseconds, on the same axis.

**`latencies.csv`** is sleep-accuracy's own wide form, unchanged: the 26
configuration columns, 2 verification columns, and the 23 columns the
tool prints. It is written only when sleep-accuracy ran. Deliberate
duplication, in one function: it keeps archived campaigns' tooling and
checksums working, and keeps a new sleep-accuracy campaign directly
comparable to them by scripts that already exist.

In a configuration column **0 means the option was not configured**;
otherwise the column holds the value in use (`realtime`, `fifo`, `80`,
`C1E+C6`, `base`, `turbo`, `high`, ...), because the actual value says
more than a bare 1.

`summary.txt` holds a per-stage table of every application's figures,
plus sleep-accuracy's own p50/p90/p99/p999/max table when it ran.

A stage that turns out to have measured a system the policy had not
configured is left out of the CSV and rerun, up to `STAGE_RETRIES`
attempts. Its logs are kept in `<stage>.unconfigured`, and the run exits
non-zero if a stage never produced a valid measurement, so a gap in the
data is visible instead of being filled with baseline numbers under a
stage's name.

The check reads the measurement itself rather than the policy's status,
because the policy reports a configuration as applied before it has
finished acting on it. `sleep-accuracy` prints the scheduling policy it
inherited, so a stage that configured a scheduling class and measured
`schedpol` 0 measured the baseline. Stages that configure no scheduling
class are checked against the plugin's record of assigning the benchmark
container to a balloon.

`openssl` and `redis` report nothing of the kind, so for them the
witness is the kernel's own view of the running process: `chrt` in the
during-benchmark snapshot, which the harness already collects. That is
an outside view rather than a self-report, which if anything makes it
better evidence; what it depends on is the snapshot existing. Hence
`SKIP_DURING_VALIDATION` is **refused** for those applications rather
than degraded — a stage with no witness at all is exactly what the rest
of this harness exists to prevent.

One application failing the check discards the whole stage and retries
it, because what failed is the stage's configuration and every
application in the stage shares it. The failure this catches is real: rewriting
thousands of IRQ affinities on a heavily loaded node can take longer than
containerd's NRI request timeout, and containerd then closes the
connection, the plugin exits with `connection to NRI/runtime lost` and
restarts, and a container created while it was away never reaches a
balloon. In a five-cycle run on a 128-CPU node under a load average of
170, this hit stage 8 twice.

The CSV can be rebuilt from stored logs without re-running anything,
since each stage directory keeps the configuration row it was run with:

```sh
./report.sh    RESULTS_DIR > latencies.csv
./report.sh -m RESULTS_DIR > metrics.csv
```

## Node requirements

Meaningful numbers need a node that actually has the mechanisms the
stages use: `cpufreq`, `cpuidle`, uncore frequency control, and SST/PCT
(`/dev/isst_interface`) for stage 8. `run-benchmark.sh` warns about
whatever is missing and records `cpu_tuning_applied=0` in the stage
environment when the policy could not apply CPU tuning, so that
unusable results are recognisable afterwards.

Stage 8 needs the plugin to run privileged with `/dev` access. The
harness passes `--set allowPCT=true` for it automatically.

The runtime has to offer NRI to the plugin. containerd enables NRI by
default since 2.0, so nothing is needed there, and the harness checks
what the runtime reports before the first stage. Only if NRI really is
off does it ask the chart to enable it with
`nri.runtime.patchConfig=true`; `PATCH_RUNTIME_CONFIG=1` forces that on.
Patching is not the default because the init container that does it
rewrites `/etc/containerd/config.toml` and restarts containerd. On a
configuration that is entirely comments, as the containerd.io packages
ship, that container also panics on a nil map, leaving the plugin stuck
in `Init:CrashLoopBackOff`.

The harness forwards any `OVERRIDE_*` variable to the plugin container,
which lets the e2e simulated-platform hooks (`OVERRIDE_SYS_CPUFREQ`,
`OVERRIDE_SYS_CSTATES`, `OVERRIDE_SST`, `OVERRIDE_SST_STATE_DIR`) drive
a run on a virtual machine that has none of this hardware. That is
useful for validating the harness and the policy's behaviour, but
latencies measured against a simulated platform say nothing about real
hardware and must not be used to draw conclusions.
