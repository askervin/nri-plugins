# Latency benchmark for the balloons policy

Measures how much the NRI balloons policy helps latency-sensitive and
realtime workloads. The metric is process wakeup latency from
`nanosleep`, with the emphasis on tail latencies (P90, P99, P999) and
variance rather than averages.

The benchmark runs
[sleep-accuracy](../sleep-accuracy) in a container through a ladder of
balloons policy configurations, starting from no policy at all and
adding one tuning mechanism per stage. Every stage runs against the
same background load, so the stages are comparable.

## The measurement never tunes anything itself

`sleep-accuracy` can set CPU frequencies, C-states, CPU affinity and
scheduling policies by itself, but this harness deliberately does not
let it: it runs the tool without `-p`, `-c`, `-f` and `-i`. Each of
those options configures nothing when it is not given, so everything
that affects latency is left to the container runtime and the balloons
policy, which is exactly what the benchmark is trying to measure.

Without `-p` the tool does not call `sched_setscheduler()` at all, and
reports the policy and priority it inherited in the `schedpol` and
`schedprio` output columns. If it did set its own policy, it would
silently erase the realtime class the balloons policy had applied and
stages 4-7 would measure nothing.

## Scripts

| Script | Purpose |
| --- | --- |
| `build-images.sh` | Builds the `sleep-accuracy` and `stress-ng` images and imports them into containerd's `k8s.io` namespace. Run once. |
| `run-benchmark.sh` | The orchestrator: runs the stage ladder and collects results. This is the entry point. |
| `gen-balloons-config.sh` | Generates a `BalloonsPolicy` from environment variables. Every field is optional; an unset variable omits the field. |
| `stages.sh` | Defines the stage ladder. Each stage is a function that sets the variables `gen-balloons-config.sh` reads. |
| `reset-node.sh` | Returns the node to a known, untuned state between stages. |
| `report.sh` | Builds the CSV and the summary table. Also usable stand-alone. |

`sleep-accuracy-job.yaml.in` and `stress-ng-deployment.yaml.in` are
templates instantiated the same way the e2e tests do it: `${VAR:-default}`
and `$(...)` expanded through `eval`.

The configuration generator is a script rather than a `.yaml.in`
template because `cpuClasses` needs nested loops over three class
prefixes, and the `$(...)`-inside-`$(...)` quoting that would require in
a template is not maintainable.

## Usage

On the Kubernetes node under test, as a user who can `sudo`:

```sh
./build-images.sh        # once
./run-benchmark.sh       # all stages
```

```sh
./run-benchmark.sh -l                                  # list stages
./run-benchmark.sh -d                                  # dry run: print configurations only
./run-benchmark.sh baseline-no-balloons realtime-sched  # selected stages
BENCH_ITERATIONS=100000 BENCH_REPEATS=5 ./run-benchmark.sh
```

Per stage the script resets the node, generates and applies the
`BalloonsPolicy`, starts the background load, runs the benchmark Job,
and appends the results to the CSV. `-k` leaves the last stage running
for inspection instead of cleaning up.

## Stage ladder

Stages 1-6 are incremental: each keeps what the previous one configured
and adds one mechanism. **Stage 7 is a replacement**, not an increment:
it drops the cpufreq and `turboPriority` arbitration of stages 5-6 and
lets PCT hardware do the priority work instead.

| # | Stage | Adds |
| --- | --- | --- |
| 1 | `baseline-no-balloons` | Nothing. No policy installed at all. |
| 2 | `default-balloon` | Policy installed, benchmark shares the default balloon with the noise. |
| 3 | `dedicated-cpus` | Own balloon with dedicated CPUs (`preferNewBalloons`). |
| 4 | `realtime-sched` | `SCHED_FIFO` priority 80 via `schedulingClasses`. |
| 5 | `disabled-cstates` | `disabledCstates: [C1E, C6]` on the benchmark's CPUs via `cpuClasses`. |
| 6 | `max-freq-turbo-prio` | `minFreq: base`, `maxFreq: turbo`, and `turboPriority` capping every other class at base. |
| 7 | `pct-priority-cores` | `pctPriority: high` on the benchmark's CPUs, `low` everywhere else. Replaces the stage 5-6 frequency controls. |

Stage 7 needs a low-priority class covering everything else, including
`idleCPUClass`: idle CPUs left outside the LP CLOS would inflate the
active high-priority core count and defeat the point.

## Background load

Every stage runs the same `stress-ng` load, so that a stage's numbers
reflect the policy and not a quiet machine. `NOISE_WORKLOAD` selects
what it burns: `cpu`, `mem` (memory bandwidth), `both` (default), or
`none`. `NOISE_REPLICAS` sets how many containers burn it (default:
half the node's CPUs).

## Results

`RESULTS_DIR` (default `results/<timestamp>`) gets one directory per
stage with the full logs: the generated `BalloonsPolicy`, the rendered
Job and Deployment, the helm values and install log, the plugin's own
log, `kubectl` output, the node state, the stage's environment, and the
raw `sleep-accuracy` output.

`latencies.csv` holds one row per measurement. The 23 configuration
columns describe what was in effect, followed by the 23 columns
`sleep-accuracy` prints. In a configuration column **0 means the option
was not configured**; otherwise the column holds the value in use
(`realtime`, `fifo`, `80`, `C1E+C6`, `base`, `turbo`, `high`, ...),
because the actual value says more than a bare 1.

`summary.txt` is a quick per-stage table of p50/p90/p99/p999/max.

The CSV can be rebuilt from stored logs without re-running anything,
since each stage directory keeps the configuration row it was run with:

```sh
./report.sh RESULTS_DIR > latencies.csv
```

## Node requirements

Meaningful numbers need a node that actually has the mechanisms the
stages use: `cpufreq`, `cpuidle`, uncore frequency control, and SST/PCT
(`/dev/isst_interface`) for stage 7. `run-benchmark.sh` warns about
whatever is missing and records `cpu_tuning_applied=0` in the stage
environment when the policy could not apply CPU tuning, so that
unusable results are recognisable afterwards.

Stage 7 needs the plugin to run privileged with `/dev` access. The
harness passes `--set allowPCT=true` for it automatically.

The harness forwards any `OVERRIDE_*` variable to the plugin container,
which lets the e2e simulated-platform hooks (`OVERRIDE_SYS_CPUFREQ`,
`OVERRIDE_SYS_CSTATES`, `OVERRIDE_SST`, `OVERRIDE_SST_STATE_DIR`) drive
a run on a virtual machine that has none of this hardware. That is
useful for validating the harness and the policy's behaviour, but
latencies measured against a simulated platform say nothing about real
hardware and must not be used to draw conclusions.
