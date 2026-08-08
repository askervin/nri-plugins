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
stages 4-8 would measure nothing.

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
and matrix instructions draw enough current that the core cannot hold its
frequency, and on server parts that licence-based downclocking reaches
every core in the domain — including one running nothing but a
latency-sensitive task that issues no vector instructions at all. It is
therefore the load that most directly tests whether the policy's
frequency and priority controls protect such a task, and the one thing a
CPU and memory bandwidth load does not exercise. Comparing a `vector`
campaign against a `both` campaign is only meaningful if nothing else
changed between them, since the stages differ in how much they can do
about frequency.

## Results

`RESULTS_DIR` (default `results/<timestamp>`) gets one directory per
stage with the full logs: the generated `BalloonsPolicy`, the rendered
Job and Deployment, the helm values and install log, the plugin's own
log, `kubectl` output, the node state, the stage's environment, and the
raw `sleep-accuracy` output.

`latencies.csv` holds one row per measurement. The 26 configuration
columns describe what was in effect, followed by the 23 columns
`sleep-accuracy` prints. In a configuration column **0 means the option
was not configured**; otherwise the column holds the value in use
(`realtime`, `fifo`, `80`, `C1E+C6`, `base`, `turbo`, `high`, ...),
because the actual value says more than a bare 1.

`summary.txt` is a quick per-stage table of p50/p90/p99/p999/max.

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
container to a balloon. The failure this catches is real: rewriting
thousands of IRQ affinities on a heavily loaded node can take longer than
containerd's NRI request timeout, and containerd then closes the
connection, the plugin exits with `connection to NRI/runtime lost` and
restarts, and a container created while it was away never reaches a
balloon. In a five-cycle run on a 128-CPU node under a load average of
170, this hit stage 8 twice.

The CSV can be rebuilt from stored logs without re-running anything,
since each stage directory keeps the configuration row it was run with:

```sh
./report.sh RESULTS_DIR > latencies.csv
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
