// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// in-place-scaling - Workers with adaptive available CPU affinity.

/*
  Debug tips:

  CPU affinity and toggling can be observed with:

    SLEEP_PID=$(pgrep in-place-scaling | sort -n | head -n 1)
    sudo bpftrace -e "tracepoint:sched:sched_stat_runtime{ if(args->pid == $SLEEP_PID) { @run[cpu]+=args->runtime } } interval:ms:100{ print(@run);  }"
*/

#define _GNU_SOURCE

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#define uint64_t u_int64_t

#define NANOSECOND  1ULL
#define MICROSECOND 1000ULL
#define MILLISECOND 1000000ULL
#define SECOND      1000000000ULL

// MAX_COMB - maximum number of combinations to test on each option
#define MAX_COMB 10

pid_t main_thread_pid = 0;

// options
typedef struct {
    int adaptation_us[MAX_COMB];     // Adaptation intervals in microseconds
    int adaptation_count;            // Number of adaptation intervals
    int worker_sleeps_us[MAX_COMB];  // Worker thread sleep durations in microseconds
    int worker_sleeps_count;         // Number of worker sleep durations
    int worker_works_us[MAX_COMB];   // Worker thread work durations in microseconds
    int worker_works_count;          // Number of worker work durations
    int workers[MAX_COMB];           // Number of workers
    int workers_count;               // Number of worker counts
    int polprio[MAX_COMB][2];        // Scheduling policy and priority pairs
    int polprio_count;               // Number of policy/priority pairs
    int cpuidle_minmax[MAX_COMB][2]; // cpuidle min/max state pairs
    int cpuidle_count;               // Number of cpuidle min/max pairs
    int cpufreq_minmax[MAX_COMB][2]; // cpufreq min/max [kHz] pairs
    int cpufreq_count;               // Number of cpufreq min/max pairs
    int iterations;                  // Number of iterations per measurement
    int repeats;                     // Number of repetitions for each measurement
} options_t;

typedef struct {
    options_t* options;
    int adaptation_idx;
    int worker_sleep_idx;
    int worker_works_idx;
    int workers_idx;
    int polprio_idx;
    int cpuidle_idx;
    int cpufreq_idx;
    int64_t idx; // -1: finished
} options_iterator_t;

options_t options = {};

void print_usage() {
    printf(
        "in-place-scaling - Workers with adaptive available CPU affinity.\n"
        "\n"
        "Usage: in-place-scaling [options]\n"
        "Comma-separated options:\n"
        "  -a <time_us,...>   Adaptation intervals: pool manager affinity change poll delay.\n"
        "  -s <time_us,...>   Worker thread sleeps, report sleep accuracy.\n"
        "  -w <time_us,...>   Worker thread work periods, report number of memory accesses.\n"
        "  -n <workers,...>   Number of workers. The default is available CPUs - 1.\n"
        "  -p <pol/prio,...>  Comma-separated list of scheduling policy/priority.\n"
        "                     0=OTHER, 1=FIFO, 2=RR, 3=BATCH, 5=IDLE (default: 0/0), see sched_setscheduler(2)\n"
        "  -i <[min/]max,...> Comma-separated list of cpuidle min/max state pairs (default: 0/99)\n"
        "  -f <min/max,...>   Comma-separated list of cpufreq min/max [kHz] pairs (default: 0/9999999) or constant frequencies\n"
        "  -I <iterations>    Number of iterations per measurement (default: 1000)\n"
        "  -R <repeats>       Number of repetitions of each measurement (default: 1)\n"
        "  -h                 Show this help message\n"
        "\n"
        "Example:\n"
        "  in-place-scaling -a 1000 -s 1000 -w 200 -p 1/10 -f 800000/2400000,2400000\n"
    );
}

// delay - sleep for specified nanoseconds
void delay(uint64_t ns) {
    struct timespec req, rem;
    req.tv_sec = ns / SECOND;
    req.tv_nsec = ns % SECOND;
    while (nanosleep(&req, &rem) == -1) {
        req = rem; // continue sleeping for the remaining time if interrupted
    }
}

// set_cpu_affinity - set CPU affinity of the main thread to a specific CPU
void set_cpu_affinity(int pid, int cpu) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  if (sched_setaffinity(pid, sizeof(cpuset), &cpuset) == -1) {
    perror("sched_setaffinity");
    exit(EXIT_FAILURE);
  }
}

void get_cpu_affinity(int pid, cpu_set_t *cpuset) {
    CPU_ZERO(cpuset);
    if (sched_getaffinity(pid, sizeof(*cpuset), cpuset) == -1) {
        perror("sched_getaffinity");
        exit(EXIT_FAILURE);
    }
}

// get_allowed_cpus_count - get number of CPUs allowed for a process
int get_allowed_cpus_count(int pid) {
    cpu_set_t cpuset;
    get_cpu_affinity(pid, &cpuset);
    int count = 0;
    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            count++;
        }
    }
    return count;
}

// set_scheduler - set scheduling policy and priority
void set_scheduler(int pid, int policy, int priority) {
    struct sched_param param;
    param.sched_priority = priority;
    if (sched_setscheduler(pid, policy, &param) == -1) {
        perror("sched_setscheduler");
        exit(EXIT_FAILURE);
    }
}

// set_cpuidle_minmax - enable/disable cpuidle/stateX's
void set_cpuidle_minmax(int cpu, int min, int max) {
    char disable_filename[1024];
    int state = 0;
    FILE *f = NULL;
    while (1) {
        sprintf(disable_filename, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/disable", cpu, state);
        FILE *f = fopen(disable_filename, "w");
        if (!f) {
            if (state == 0 && max != 99) {
                perror("cannot open for writing: cpuidle/state0/disable");
            }
            break; // all cpuidle states processed
        }
        fprintf(f, "%d\n", (state < min || state > max) ? 1 : 0);
        fflush(f);
        fsync(fileno(f));
        fclose(f);
        state++;
    }
    if (f) fclose(f);
}

// get_cpuidle_minmax - read min and max cpuidle states for the CPU from sysfs
void get_cpuidle_minmax(int cpu, int *min, int *max) {
    char disable_filename[1024];
    int state = 0;
    FILE *f = NULL;
    *min = -1;
    *max = -1;
    while (1) {
        sprintf(disable_filename, "/sys/devices/system/cpu/cpu%d/cpuidle/state%d/disable", cpu, state);
        f = fopen(disable_filename, "r");
        if (!f) {
            break; // all cpuidle states processed
        }
        int disabled = 0;
        fscanf(f, "%d", &disabled);
        fclose(f);
        if (!disabled) {
            if (*min == -1) *min = state;
            *max = state;
        }
        state++;
    }
}

// set_cpufreq_minmax - set min and max cpufreq for the CPU in sysfs
void set_cpufreq_minmax(int cpu, int min, int max) {
    char freq_filename[1024];
    FILE *f = NULL;

    sprintf(freq_filename, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
    f = fopen(freq_filename, "w");
    if (f) {
        fprintf(f, "%d\n", max);
        fflush(f);
        fsync(fileno(f));
        fclose(f);
    } else {
        perror("cannot open for writing: cpufreq/scaling_max_freq");
    }

    sprintf(freq_filename, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_min_freq", cpu);
    f = fopen(freq_filename, "w");
    if (f) {
        fprintf(f, "%d\n", min);
        fflush(f);
        fsync(fileno(f));
        fclose(f);
    } else {
        perror("cannot open for writing: cpufreq/scaling_min_freq");
    }
}

// get_cpufreq_minmax - read min and max cpufreq for the CPU from sysfs
void get_cpufreq_minmax(int cpu, int *min, int *max) {
    char freq_filename[1024];
    FILE *f = NULL;

    sprintf(freq_filename, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
    f = fopen(freq_filename, "r");
    if (f) {
        fscanf(f, "%d", max);
        fclose(f);
    } else {
        perror("cannot open for reading: cpufreq/scaling_max_freq");
    }

    sprintf(freq_filename, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_min_freq", cpu);
    f = fopen(freq_filename, "r");
    if (f) {
        fscanf(f, "%d", min);
        fclose(f);
    } else {
        perror("cannot open for reading: cpufreq/scaling_min_freq");
    }
}

// get_time_ns - get current time in nanoseconds
uint64_t get_time_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * SECOND + (uint64_t)ts.tv_nsec;
}

// compare_uint64 - comparison function for qsort
int compare_uint64(const void *a, const void *b) {
  uint64_t val1 = *(const uint64_t *)a;
  uint64_t val2 = *(const uint64_t *)b;
  if (val1 < val2) return -1;
  if (val1 > val2) return 1;
  return 0;
}

// busy-wait for a specified duration
void busy_wait(uint64_t duration_ns) {
    u_int64_t start = get_time_ns();
    while (get_time_ns() - start < duration_ns);
}

// measure - perform measurements (all iterations) of sleep latency
void measure(int64_t busy_ns, int64_t sleep_ns, int64_t *out_latencies) {
    int64_t iters = options.iterations;

    for (int i = 0; i < iters; i++) {
        // TODO: implement busy work before sleep
        if (busy_ns > 0) {
            busy_wait(busy_ns);  // Simulate work before sleep
        }
        int64_t sleep_start = get_time_ns();

        // request a short sleep using nanosleep, even if sleep_ns is 0
        if (sleep_ns >= 0) {
            struct timespec req = {0, sleep_ns};
            nanosleep(&req, NULL);
        }

        int64_t sleep_end = get_time_ns();

        int64_t actual_sleep = sleep_end - sleep_start;

        int64_t latency;
        if (sleep_ns >= 0) {
            latency = actual_sleep - sleep_ns;
        } else {
            latency = actual_sleep;
        }

        out_latencies[i] = latency;
    }
}

void print_latencies(int64_t *latencies) {
    uint64_t total_latency = 0;
    int64_t iters = options.iterations;
    for (int i = 0; i < iters; i++) {
        total_latency += latencies[i];
    }

    // Sort latencies for percentile calculation
    qsort(latencies, iters, sizeof(uint64_t), compare_uint64);

    double avg_latency = (double)total_latency / iters;

    // Calculate percentiles
    int64_t min = latencies[0];
    int64_t p5 = latencies[(int)(iters * 0.05)];
    int64_t p50 = latencies[(int)(iters * 0.5)];
    int64_t p80 = latencies[(int)(iters * 0.8)];
    int64_t p90 = latencies[(int)(iters * 0.9)];
    int64_t p95 = latencies[(int)(iters * 0.95)];
    int64_t p99 = latencies[(int)(iters * 0.99)];
    int64_t p999 = latencies[(int)(iters * 0.999)];
    int64_t max = latencies[iters - 1];

    // Print results
    printf("%ld %ld %ld %ld %ld %ld %ld %ld %ld %.0f", min, p5, p50, p80, p90, p95, p99, p999, max, avg_latency);
}

void parse_options(int argc, char *argv[], options_t* options) {
    // Set default values
    memset(options, 0, sizeof(options_t));

    options->adaptation_us[options->adaptation_count++] = 1000; // Default adaptation interval 1000 us

    options->worker_sleeps_us[options->worker_sleeps_count++] = 1000; // Default worker sleep 1000 us

    options->worker_works_us[options->worker_works_count++] = 200; // Default worker work 200 us

    options->workers[options->workers_count++] = get_allowed_cpus_count(0) - 1; // Default number of workers: available CPUs - 1

    options->polprio[options->polprio_count][0] = 0; // Default policy OTHER
    options->polprio[options->polprio_count++][1] = 0; // Default priority 0

    options->cpuidle_minmax[options->cpuidle_count][0] = 0; // Default cpuidle min state
    options->cpuidle_minmax[options->cpuidle_count++][1] = 99; // Default cpuidle max state

    options->cpufreq_minmax[options->cpufreq_count][0] = 0; // Default cpufreq min [kHz]
    options->cpufreq_minmax[options->cpufreq_count++][1] = 9999999; // Default cpufreq max [kHz]

    options->repeats = 1;
    options->iterations = 1000;

    // Parse command-line arguments and override defaults
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) { // adaptation intervals
            options->adaptation_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->adaptation_count < MAX_COMB) {
                options->adaptation_us[options->adaptation_count++] = atoi(token);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) { // worker sleeps
            options->worker_sleeps_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->worker_sleeps_count < MAX_COMB) {
                options->worker_sleeps_us[options->worker_sleeps_count++] = atoi(token);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) { // worker works
            options->worker_works_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->worker_works_count < MAX_COMB) {
                options->worker_works_us[options->worker_works_count++] = atoi(token);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) { // number of workers
            options->workers_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->workers_count < MAX_COMB) {
                options->workers[options->workers_count++] = atoi(token);
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) { // scheduling policy/priority
            options->polprio_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->polprio_count < MAX_COMB) {
                char *slash = strchr(token, '/');
                if (slash) {
                    *slash = '\0';
                    options->polprio[options->polprio_count][0] = atoi(token);
                    options->polprio[options->polprio_count++][1] = atoi(slash + 1);
                }
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) { // cpuidle min/max
            options->cpuidle_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->cpuidle_count < MAX_COMB) {
                char *slash = strchr(token, '/');
                if (slash) {
                    *slash = '\0';
                    options->cpuidle_minmax[options->cpuidle_count][0] = atoi(token);
                    options->cpuidle_minmax[options->cpuidle_count++][1] = atoi(slash + 1);
                } else {
                    // Without slash, idle sets only max cstate, min=0
                    options->cpuidle_minmax[options->cpuidle_count][0] = 0;
                    options->cpuidle_minmax[options->cpuidle_count++][1] = atoi(token);
                }
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) { // cpufreq min/max
            options->cpufreq_count = 0; // Reset defaults
            char *token = strtok(argv[++i], ",");
            while (token && options->cpufreq_count < MAX_COMB) {
                char *slash = strchr(token, '/');
                if (slash) {
                    *slash = '\0';
                    options->cpufreq_minmax[options->cpufreq_count][0] = atoi(token);
                    options->cpufreq_minmax[options->cpufreq_count++][1] = atoi(slash + 1);
                } else {
                    // Without slash, freq is constant (set min and max)
                    options->cpufreq_minmax[options->cpufreq_count][0] = atoi(token);
                    options->cpufreq_minmax[options->cpufreq_count++][1] = atoi(token);
                }
                token = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "-I") == 0 && i + 1 < argc) {
            options->iterations = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-R") == 0 && i + 1 < argc) {
            options->repeats = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            exit(0);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }
}

options_t* new_options() {
    options_t* options = malloc(sizeof(options_t));
    if (!options) {
        perror("allocating memory for options failed");
        exit(EXIT_FAILURE);
    }
    memset(options, 0, sizeof(options_t));
    return options;
}

options_iterator_t* new_options_iterator(options_t* options) {
    options_iterator_t* iterator = malloc(sizeof(options_iterator_t));
    if (!iterator) {
        perror("allocating memory for options iterator failed");
        exit(EXIT_FAILURE);
    }
    memset(iterator, 0, sizeof(options_iterator_t));
    iterator->options = options;
    return iterator;
}

void options_iterator_next(options_iterator_t** iterptr) {
    options_iterator_t* iter = *iterptr;
    options_t* options = iter->options;
    int64_t multiplier = 1;

    if (iter == NULL || iter->idx == -1) return;
    iter->idx++;

    iter->polprio_idx = (iter->idx / multiplier) % options->polprio_count;
    multiplier *= options->polprio_count;

    iter->workers_idx = (iter->idx / multiplier) % options->workers_count;
    multiplier *= options->workers_count;

    iter->worker_works_idx = (iter->idx / multiplier) % options->worker_works_count;
    multiplier *= options->worker_works_count;

    iter->worker_sleep_idx = (iter->idx / multiplier) % options->worker_sleeps_count;
    multiplier *= options->worker_sleeps_count;

    iter->adaptation_idx = (iter->idx / multiplier) % options->adaptation_count;
    multiplier *= options->adaptation_count;

    iter->cpufreq_idx = (iter->idx / multiplier) % options->cpufreq_count;
    multiplier *= options->cpufreq_count;

    iter->cpuidle_idx = (iter->idx / multiplier) % options->cpuidle_count;
    multiplier *= options->cpuidle_count;

    if (iter->idx / multiplier >= 1) {
        free(iter);
        *iterptr = NULL;
    }
}

void configure_cpus(options_iterator_t* iter, cpu_set_t *original_cpuset) {
    static int last_cpuidle_min = -1;
    static int last_cpuidle_max = -1;
    static int last_cpufreq_min = -1;
    static int last_cpufreq_max = -1;
    int last_allowed_cpu = -1;
    options_t* options = iter->options;

    int cpuidle_min = options->cpuidle_minmax[iter->cpuidle_idx][0];
    int cpuidle_max = options->cpuidle_minmax[iter->cpuidle_idx][1];
    int cpufreq_min = options->cpufreq_minmax[iter->cpufreq_idx][0];
    int cpufreq_max = options->cpufreq_minmax[iter->cpufreq_idx][1];

    // Set cpuidle and cpufreq for all allowed CPUs if changed
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, original_cpuset)) {
            if (cpuidle_min != last_cpuidle_min || cpuidle_max != last_cpuidle_max) {
                set_cpuidle_minmax(cpu, cpuidle_min, cpuidle_max);
            }
            if (cpufreq_min != last_cpufreq_min || cpufreq_max != last_cpufreq_max) {
                set_cpufreq_minmax(cpu, cpufreq_min, cpufreq_max);
            }
            last_allowed_cpu = cpu;
        }
    }
    last_cpuidle_min = cpuidle_min;
    last_cpuidle_max = cpuidle_max;
    last_cpufreq_min = cpufreq_min;
    last_cpufreq_max = cpufreq_max;
    // TODO: if changed, observe the values from the last configured CPU
    delay(100 * MILLISECOND); // wait for settings to take effect
    get_cpufreq_minmax(last_allowed_cpu, &cpufreq_min, &cpufreq_max);
    get_cpuidle_minmax(last_allowed_cpu, &cpuidle_min, &cpuidle_max);
    printf("DEBUG: configure_cpus: cpuidle states [%d..%d], cpufreq [%d..%d] kHz\n", cpuidle_min, cpuidle_max, cpufreq_min, cpufreq_max);
}

void restore_cpus(cpu_set_t *original_cpuset) {
    int last_allowed_cpu = -1;
    // Restore original cpuidle and cpufreq settings for all allowed CPUs
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, original_cpuset)) {
            set_cpuidle_minmax(cpu, 0, 99); // enable all cpuidle states
            set_cpufreq_minmax(cpu, 0, 9999999); // set cpufreq to min=0, max=very high
            last_allowed_cpu = cpu;
        }
    }
    int cpuidle_min, cpuidle_max, cpufreq_min, cpufreq_max;
    delay(100 * MILLISECOND); // wait for settings to take effect
    get_cpufreq_minmax(last_allowed_cpu, &cpufreq_min, &cpufreq_max);
    get_cpuidle_minmax(last_allowed_cpu, &cpuidle_min, &cpuidle_max);
    printf("DEBUG: restore_cpus: cpuidle states [%d..%d], cpufreq [%d..%d] "
           "kHz\n",
           cpuidle_min, cpuidle_max, cpufreq_min, cpufreq_max);
}

typedef enum {
  WPM_ORDER_NONE = 0,
  WPM_ORDER_EXIT = 1 << 0,
  WPM_ORDER_ONESHOT = 1 << 1, // WPM_ORDER_ONESHOT must match WPM_STATUS_ONESHOT
  WPM_ORDER_WORK = 1 << 2,
  WPM_ORDER_SLEEP = 1 << 3,
  WPM_ORDER_ONESHOT_WRITE = 1 << 4,
  WPM_ORDER_ONESHOT_READ = 1 << 5,
  WPM_ORDER_ONESHOT_TOGGLEBIT = 1 << 6,
  WPM_ORDER_REPORT_CYCLES = 1 << 7,
} wpm_orders_t;

wpm_orders_t oneshot_orders = WPM_ORDER_ONESHOT_WRITE | WPM_ORDER_ONESHOT_READ | WPM_ORDER_ONESHOT_TOGGLEBIT;

typedef enum {
    WPM_STATUS_NONE = 0,
    WPM_STATUS_STARTED = 1 << 0,
    WPM_STATUS_ONESHOT = 1 << 1, // WPM_STATUS_ONESHOT must match WPM_ORDER_ONESHOT
    WPM_STATUS_WRITING_PIPE = 1 << 2,
    WPM_STATUS_READING_PIPE = 1 << 3,
    WPM_STATUS_TOGGLEBIT = 1 << 4,
    WPM_STATUS_EXITED = 1 << 5,
} wpm_status_t;

typedef struct {
    int worker_id;
    int pid;
    // orders: manager writes, worker reads
    volatile wpm_orders_t orders;
    // status: manager reads, worker writes
    volatile wpm_status_t status;
    // cycles: updated by worker
    volatile int64_t cycles;
    // pipe for manager-worker communication
    int pipe_to_worker[2];
    int pipe_from_worker[2];
    // reserved padding
    char reserved[256 - sizeof(int)*2 - sizeof(wpm_orders_t) - sizeof(wpm_status_t) - sizeof(int64_t) - sizeof(int) * 2];
} wpm_worker_shm_t;

int wpm_worker(options_iterator_t* iter, wpm_worker_shm_t* shm) {
    const int max_msg_size = 1024;
    options_t* options = iter->options;
    int worker_sleep_us = options->worker_sleeps_us[iter->worker_sleep_idx];
    int worker_work_us = options->worker_works_us[iter->worker_works_idx];
    char buffer_with_header[max_msg_size + 64];
    sprintf(buffer_with_header, "worker %d: ", shm->worker_id);
    char* buffer = buffer_with_header + strlen(buffer_with_header) - 1;
    int64_t cycles = 0;
    wpm_orders_t cmd = WPM_ORDER_NONE;

    shm->status = WPM_STATUS_STARTED;
    while (((cmd = shm->orders) & WPM_ORDER_EXIT) == 0) {
        // Simulate work
        if (cmd & WPM_ORDER_WORK && worker_work_us > 0) {
            busy_wait(worker_work_us * MICROSECOND);
            cmd = shm->orders;
        }
        // Sleep
        if (cmd & WPM_ORDER_SLEEP && worker_sleep_us > -1) {
            delay(worker_sleep_us * MICROSECOND);
            cmd = shm->orders;
        }

        int64_t status = shm->status;
        // Run oneshot operations when ordered oneshot bit and taken oneshot bits differ
        if ((cmd & WPM_ORDER_ONESHOT) != (status & WPM_STATUS_ONESHOT)) {
            // Read from pipe
            if (cmd & WPM_ORDER_ONESHOT_READ) {
                shm->status = status | WPM_STATUS_READING_PIPE;
                ssize_t n = read(shm->pipe_to_worker[0], buffer, max_msg_size - 1);
                shm->status = status;
                if (n > 0) {
                    buffer[n] = '\0';
                }
            }
            // Write to pipe
            if (cmd & WPM_ORDER_ONESHOT_WRITE) {
                shm->status = status | WPM_STATUS_WRITING_PIPE;
                write(shm->pipe_from_worker[1], buffer_with_header, strlen(buffer_with_header));
                shm->status = status;
            }
            // Toggle bit
            if (cmd & WPM_ORDER_ONESHOT_TOGGLEBIT) {
                status = status ^ WPM_STATUS_TOGGLEBIT;
            }
            // Flip the status of the taken oneshot bit match the ordered oneshot bit
            shm->status = status ^ WPM_STATUS_ONESHOT;
        }
        // Report cycles
        if (cmd & WPM_ORDER_REPORT_CYCLES) {
            shm->cycles = cycles;
        }
        cycles++;
    }
    shm->cycles = cycles;
    shm->status = WPM_STATUS_EXITED;
    return 0;
}

void wpm_worker_pipe_write(wpm_worker_shm_t* shm, const char* message) {
    write(shm->pipe_to_worker[1], message, strlen(message));
}

void wpm_worker_pipe_read(wpm_worker_shm_t* shm, char* buffer, size_t buffer_size) {
    ssize_t n = read(shm->pipe_from_worker[0], buffer, buffer_size - 1);
    if (n > 0) {
        buffer[n] = '\0';
    }
}

void wpm_worker_pipe_query(wpm_worker_shm_t* shm, const char* query, char* response, size_t response_size) {
    int worker_id = shm->worker_id;
    uint64_t start_ns = get_time_ns();
    wpm_worker_pipe_write(shm, query);
    wpm_worker_pipe_read(shm, response, response_size);
    uint64_t end_ns = get_time_ns();
    printf("DEBUG: wpm_pipe_query_worker: in %ld ns received from worker %d: %s\n", end_ns-start_ns, worker_id, response);
}

static inline void wpm_workers_oneshot_orders(wpm_worker_shm_t* shm, wpm_orders_t orders) {
    int ordered = (shm->orders & WPM_ORDER_ONESHOT) != 0;
    int taken = (shm->status & WPM_STATUS_ONESHOT) != 0;
    if (ordered != taken) {
        printf("DEBUG: worker %d (pid %d) oneshot busy\n", shm->worker_id, shm->pid);
        pause();
        perror("wpm_oneshot_worker: previous oneshot not finished");
        return;
    }
    shm->orders = ((shm->orders & (~oneshot_orders)) | orders) ^ WPM_ORDER_ONESHOT;
}

void wpm_workers_pipe_ping(wpm_worker_shm_t** shms) {
    const int max_msg_size = 1024;
    char buffer[max_msg_size];
    for (wpm_worker_shm_t** shmp = shms; *shmp != NULL; shmp++) {
        wpm_workers_oneshot_orders(*shmp, WPM_ORDER_ONESHOT_WRITE | WPM_ORDER_ONESHOT_READ);
    }
    for (wpm_worker_shm_t** shmp = shms; *shmp != NULL; shmp++) {
        wpm_worker_shm_t* shm = *shmp;
        wpm_worker_pipe_query(shm, "ping", buffer, max_msg_size);
    }
}

void wpm_worker_togglebit(wpm_worker_shm_t* shm) {
    int worker_id = shm->worker_id;
    int64_t initial_status = shm->status & WPM_STATUS_TOGGLEBIT;
    int64_t current_status;
    uint64_t start_ns = get_time_ns();
    wpm_workers_oneshot_orders(shm, WPM_ORDER_ONESHOT_TOGGLEBIT);
    // wait for status bit to change
    while ((current_status=(shm->status & WPM_STATUS_TOGGLEBIT)) == initial_status) {
        // busy wait
    }
    uint64_t end_ns = get_time_ns();
    printf("DEBUG: wpm_togglebit_worker: in %ld ns worker %d toggled bit from %d to %d\n", end_ns - start_ns, worker_id, initial_status != 0, current_status != 0);
}

void wpm_workers_togglebit(wpm_worker_shm_t** shms) {
    for (wpm_worker_shm_t** shmp = shms; *shmp != NULL; shmp++) {
        wpm_worker_togglebit(*shmp);
    }
}

void wpm_workers_wait_status(wpm_worker_shm_t** shms, wpm_status_t status_bit) {
    for (wpm_worker_shm_t** shmp = shms; *shmp != NULL; shmp++) {
        wpm_worker_shm_t* shm = *shmp;
        int worker = shm->worker_id;
        while (!(shm->status & status_bit)) {
            printf("DEBUG: wpm_wait_status: waiting for worker %d status 0x%x, current status: 0x%x, cycles: %ld\n", worker, status_bit, shm->status, shm->cycles);
            delay(100 * MILLISECOND);
        }
    }
}

int wpm_workers_create(options_iterator_t* iter, wpm_worker_shm_t** shms, wpm_orders_t orders) {
    int num_workers = iter->options->workers[iter->workers_idx];

    for (int worker=0; worker<num_workers; worker++) {
        wpm_worker_shm_t* shm = shms[worker];
        int pipe_from_worker_fds[2] = {0};
        int pipe_to_worker_fds[2] = {0};
        if (pipe(pipe_from_worker_fds) == -1 || pipe(pipe_to_worker_fds) == -1) {
            perror("wpm_create_workers: pipe failed");
            exit(EXIT_FAILURE);
        }
        if (!shm) {
            perror("wpm_create_workers: malloc failed");
            exit(EXIT_FAILURE);
        }
        shm->worker_id = worker;
        shm->pipe_to_worker[0] = pipe_to_worker_fds[0];
        shm->pipe_to_worker[1] = pipe_to_worker_fds[1];
        shm->pipe_from_worker[0] = pipe_from_worker_fds[0];
        shm->pipe_from_worker[1] = pipe_from_worker_fds[1];

        shm->orders = orders;
        pid_t pid = fork();
        if (pid == -1) {
            perror("wpm_create_workers: fork failed");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // Child process - worker
            shm->pid = getpid();
            prctl(PR_SET_PDEATHSIG, SIGTERM); // ensure worker exits if parent dies
            close(pipe_from_worker_fds[0]); // close read end in worker
            close(pipe_to_worker_fds[1]); // close write end in worker
            wpm_worker(iter, shm);
            exit(0);
        } else {
            // Parent process - manager
            close(pipe_from_worker_fds[1]); // close write end in manager
            close(pipe_to_worker_fds[0]); // close read end in manager
        }
    }
    wpm_workers_wait_status(shms, WPM_STATUS_STARTED);
    return 0;
}

void wpm_workers_destroy(wpm_worker_shm_t** shms) {
    for (wpm_worker_shm_t** shmp = shms; *shmp != NULL; shmp++) {
        (*shmp)->orders = WPM_ORDER_EXIT;
        // CONTRACT? could be reading/writing pipe, too? get it from status?
    }
    delay(100 * MILLISECOND); // give workers time to process exit order
    // wait for all workers to exit
    for (wpm_worker_shm_t** shmp = shms; *shmp != NULL; shmp++) {
        wpm_worker_shm_t* shm = *shmp;
        int worker = shm->worker_id;
        while (!(shm->status & WPM_STATUS_EXITED)) {
            printf("DEBUG: wpm_stop_workers: waiting for worker %d to exit, current orders: 0x%x status: 0x%x, cycles: %ld\n", worker, shm->orders, shm->status, shm->cycles);
            kill(shm->pid, SIGTERM); // force kill if needed
            break;
        }
        close(shm->pipe_from_worker[0]);
        close(shm->pipe_to_worker[1]);
        printf("DEBUG: wpm_stop_workers: worker %d exited after %ld cycles\n", worker, shm->cycles);
    }
}

void wpm_set_sched(options_iterator_t* iter, wpm_worker_shm_t** shms) {
    options_t* options = iter->options;
    int policy = options->polprio[iter->polprio_idx][0];
    int priority = options->polprio[iter->polprio_idx][1];
    int num_workers = options->workers[iter->workers_idx];
    printf("DEBUG: main thread (pid %d) set to policy %d priority %d\n", getpid(), policy, priority);
    set_scheduler(0, policy, priority);
    for (int worker=0; worker<num_workers; worker++) {
        wpm_worker_shm_t* shm = shms[worker];
        printf("DEBUG: worker %d (pid %d) set to policy %d priority %d\n", shm->worker_id, shm->pid, policy, priority);
        set_scheduler(shm->pid, policy, priority);
    }
}

void wpm_set_cpu_affinity(options_iterator_t* iter, wpm_worker_shm_t** shms, cpu_set_t current_cpuset) {
    options_t* options = iter->options;
    int num_workers = options->workers[iter->workers_idx];

    // Assign each worker to a different CPU from the allowed set, avoiding CPU 0
    int assign_next = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE && assign_next < num_workers; cpu++) {
        if (CPU_ISSET(cpu, &current_cpuset) && cpu != 0) {
            if (assign_next == -1) {
                set_cpu_affinity(0, cpu); // set main thread to first allowed CPU
                printf("DEBUG: main thread (pid %d) assigned to CPU %d\n", getpid(), cpu);
            } else {
                wpm_worker_shm_t* shm = shms[assign_next];
                set_cpu_affinity(shm->pid, cpu);
                printf("DEBUG: worker %d (pid %d) assigned to CPU %d\n", shm->worker_id, shm->pid, cpu);
            }
            assign_next++;
        }
    }
}

void wpm_allocate_shms(options_iterator_t* iter, wpm_worker_shm_t*** out_shms) {
    int num_workers = iter->options->workers[iter->workers_idx];

    wpm_worker_shm_t** shms = malloc(sizeof(wpm_worker_shm_t*) * (num_workers+1));
    if (!shms) {
        perror("wpm_allocate_shms: malloc shms failed");
        exit(EXIT_FAILURE);
    }

    memset(shms, 0, sizeof(wpm_worker_shm_t*) * (num_workers+1));

    for (int worker=0; worker<num_workers; worker++) {
        shms[worker] = mmap(NULL, sizeof(wpm_worker_shm_t),
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS,
                            -1, 0);
        if (!shms[worker]) {
            perror("wpm_allocate_shms: malloc shm failed");
            exit(EXIT_FAILURE);
        }
        printf("DEBUG: worker %d shm allocated at %p\n", worker, shms[worker]);
        memset(shms[worker], 0, sizeof(wpm_worker_shm_t));
    }
    *out_shms = shms;
}

int worker_pool_manager(options_iterator_t* iter) {
    // shms are shared memory between workers and the manager.
    // Separately allocate own shm for each worker to avoid cache lines sharing.
    int num_workers = iter->options->workers[iter->workers_idx];
    cpu_set_t current_cpuset;

    wpm_worker_shm_t** shms;

    wpm_allocate_shms(iter, &shms);

    wpm_workers_create(iter, shms, WPM_ORDER_WORK | WPM_ORDER_SLEEP);

    get_cpu_affinity(0, &current_cpuset);
    wpm_set_cpu_affinity(iter, shms, current_cpuset);
    wpm_set_sched(iter, shms);

    delay(1 * SECOND); // sleep 1 second for testing

    for (int i=0; i<iter->options->iterations; i++) {
        wpm_workers_togglebit(shms);
    }
    for (int i=0; i<iter->options->iterations; i++) {
        wpm_workers_pipe_ping(shms);
    }

    wpm_workers_destroy(shms);

    for (int worker=0; worker<num_workers; worker++) {
        munmap(shms[worker], sizeof(wpm_worker_shm_t));
    }
    free(shms);
    printf("worker_pool_manager exited\n");
    return 0;
}

int main(int argc, char *argv[]) {
    options_t *options;
    int64_t *latencies;
    cpu_set_t original_cpuset;

    get_cpu_affinity(0, &original_cpuset);

    options = new_options();
    parse_options(argc, argv, options);

    latencies = malloc(sizeof(int64_t) * options->iterations);
    if (!latencies) {
        perror("allocating memory for latencies failed");
        exit(EXIT_FAILURE);
    }

    main_thread_pid = getpid();

    printf("round cpu0 cpu1 cpumigr_ns schedpol schedprio idlemin idlemax freqmin freqmax busy_ns sleep_ns min p5 p50 p80 p90 p95 p99 p999 max avg\n");

    for (int r = 0; r < options->repeats; r++) {
        for (options_iterator_t* iter = new_options_iterator(options); iter != NULL; options_iterator_next(&iter)) {
            // Debug: show current combination
            printf("# r=%d combination %ld: adaptation=%d us, worker_sleep=%d us, worker_work=%d us, workers=%d, pol=%d, prio=%d, cpuidle_min=%d, cpuidle_max=%d, cpufreq_min=%d kHz, cpufreq_max=%d kHz\n",
                   r,
                   iter->idx,
                   options->adaptation_us[iter->adaptation_idx],
                   options->worker_sleeps_us[iter->worker_sleep_idx],
                   options->worker_works_us[iter->worker_works_idx],
                   options->workers[iter->workers_idx],
                   options->polprio[iter->polprio_idx][0],
                   options->polprio[iter->polprio_idx][1],
                   options->cpuidle_minmax[iter->cpuidle_idx][0],
                   options->cpuidle_minmax[iter->cpuidle_idx][1],
                   options->cpufreq_minmax[iter->cpufreq_idx][0],
                   options->cpufreq_minmax[iter->cpufreq_idx][1]
                );
            configure_cpus(iter, &original_cpuset);
            worker_pool_manager(iter);
        }
    }

    // // print measurement parameters and results
    // printf("%d %d %d %ld %d %d %d %d %d %d %ld %ld ", r + 1,
    //        // TODO: number of allowed cpus in the beginning
    //        options.polprio[pp_idx][0],
    //        options.polprio[pp_idx][1],
    //        cpuidle_min,
    //        cpuidle_max,
    //        cpufreq_min,
    //        cpufreq_max,
    //     );
    // print_latencies(latencies);
    printf("TODO: results\n");
    fflush(stdout);

    free(latencies);
    free(options);
    restore_cpus(&original_cpuset);
}
