#!/bin/bash

# apps.sh - the applications the ladder can measure.
#
# Sourced by run-benchmark.sh. Each application lives in apps/<name>.sh
# and defines functions named after it, the same naming-convention
# dispatch stages.sh uses for stages: "declare -F app_<name>_manifest"
# is what decides whether an application exists.
#
#   app_<name>_defaults()   set APP_* and the application's own variables
#   app_<name>_manifest()   print the Job/Deployment yaml on stdout
#   app_<name>_start()      optional: bring up what the Job needs first
#   app_<name>_stop()       optional: tear that down again
#   app_<name>_metrics()    raw log -> canonical metric rows on stdout
#   app_<name>_witness()    optional: what the app's own output proves
#
# The variables app_<name>_defaults sets are the whole of what the
# harness needs in order to supervise an application it knows nothing
# else about:
#
#   APP_NAME              the application's own name
#   APP_LOG               raw output, relative to the stage directory
#   APP_JOB_NAME          the Job to wait for completion on
#   APP_POD_SELECTOR      label selector finding that Job's pod
#   APP_SUBJECT_POD       whose cgroup is "the benchmark's cpuset"
#   APP_SUBJECT_PROCESS   what pgrep -x should find while it runs
#   APP_ARGS              the container's arguments, for the record
#   APP_NEEDS_CLIENT      non-empty: the run needs a client balloon
#
# For an application with a separate load generator the subject is the
# *server*: the server is what sits in the balloon under test, so the
# server's cpuset, cgroup and scheduling policy are what every state
# check has to be about.
#
# The invariant every application obeys: it runs in the same balloon,
# with the same pod label, requesting the same CPUs. BENCH_LABEL_KEY,
# BENCH_LABEL_VALUE, BENCH_CPUS, BENCH_CPU_REQUEST and BENCH_MEM_REQUEST
# are shared and application-independent, so a difference between two
# applications is not partly a difference in what the policy was asked
# to do -- and so stages.sh needs no application-specific knowledge.

# APPS - every application with a module, in the order the modules were
# found. Filled in below.
APPS=()

# app_prefix APP - the environment variable prefix for APP: the name
# uppercased with dashes turned into underscores, so that
# "sleep-accuracy" reads SLEEP_ACCURACY_* and needs no lookup table.
# SLEEP_ACCURACY_IMAGE already followed this convention before there
# were modules, which is why nothing had to be renamed.
app_prefix() {
    local p="${1^^}"
    echo "${p//-/_}"
}

# app_var APP SUFFIX [DEFAULT] - the value of <PREFIX>_<SUFFIX>, or
# DEFAULT when it is unset or empty.
app_var() {
    local name value
    name="$(app_prefix "$1")_$2"
    value="${!name:-}"
    echo "${value:-${3:-}}"
}

# app_exists APP - is APP a known application?
app_exists() {
    declare -F "app_${1}_manifest" >/dev/null
}

# app_reset_vars - clear the supervision variables, so that one
# application never inherits another's.
app_reset_vars() {
    unset APP_NAME APP_LOG APP_JOB_NAME APP_POD_SELECTOR
    unset APP_SUBJECT_POD APP_SUBJECT_PROCESS APP_ARGS APP_NEEDS_CLIENT
    unset APP_SHELL APP_SHELL_B64 APP_TIMEOUT
}

# app_shell SCRIPT - encode a container entrypoint script so that it can
# be carried through a yaml template as one word.
#
# The templates are expanded with eval inside a double-quoted string, so
# a multi-word shell script with its own quotes cannot be written into
# one literally without an unmaintainable amount of escaping. Base64 is
# made of characters no shell or YAML parser has an opinion about, so the
# manifest carries "echo B64 | base64 -d | sh" and the readable script is
# written into the stage directory beside it.
app_shell() {
    APP_SHELL="$1"
    APP_SHELL_B64="$(printf '%s' "$1" | base64 -w0)"
}

# Source every module. Kept last, so the helpers above are available to
# the modules themselves.
for _app_module in "$SCRIPT_DIR"/apps/*.sh; do
    [ -f "$_app_module" ] || continue
    # shellcheck disable=SC1090
    source "$_app_module"
    _app_name="$(basename "$_app_module" .sh)"
    app_exists "$_app_name" && APPS+=("$_app_name")
done
unset _app_module _app_name
