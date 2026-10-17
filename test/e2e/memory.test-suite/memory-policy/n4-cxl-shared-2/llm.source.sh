# Helpers for running a small language model (LLM) from shared CXL memory in
# the VMs of n4-cxl-shared-1 and n4-cxl-shared-2 (test16-cxl-llm-share).
#
# The model is Qwen3-0.6B Q4_K_M, a GGUF file pinned by its Hugging Face
# commit and sha256, cached on the host in $CACHE_DIR/llm. The engine is
# cxl-llm (cxl-llm/cxl-llm.cpp, built by cxl-llm/build.sh on llama.cpp): it
# answers a prompt with the model mapped from a devdax device or from a
# regular file, and writes a model into a devdax device. The VMs get the
# engine as $LLM_VM_BIN, and the VM of the writer gets the model under
# $LLM_VM_DIR/model; pods mount them from the node (hostPath). cxl-where.py
# shows whether the page frames of the model mapping of a reader are CXL
# memory or DRAM.
#
# The helpers that work on either VM take VMDIR first, like those of
# pool.source.sh and dra.source.sh.

LLM_HELPER_DIR="$(dirname "${BASH_SOURCE[0]}")"
LLM_MODEL_REPO=unsloth/Qwen3-0.6B-GGUF
LLM_MODEL_COMMIT=50968a4468ef4233ed78cd7c3de230dd1d61a56b
LLM_MODEL_FILE=Qwen3-0.6B-Q4_K_M.gguf
LLM_MODEL_URL="https://huggingface.co/$LLM_MODEL_REPO/resolve/$LLM_MODEL_COMMIT/$LLM_MODEL_FILE"
LLM_MODEL_SHA256=ac2d97712095a558e31573f62f466a3f9d93990898b0ec79d7c974c1780d524a
LLM_MODEL_SIZE=396705472           # bytes
LLM_CACHE="${CACHE_DIR:-$HOME/.cache/nri-plugins/e2e}/llm"
LLM_VM_DIR=/opt/cxl-llm            # in the VMs
LLM_VM_BIN="$LLM_VM_DIR/cxl-llm"
LLM_VM_MODEL="$LLM_VM_DIR/model/$LLM_MODEL_FILE"
LLM_VM_WHERE=/usr/local/bin/cxl-where.py
LLM_STOP=/tmp/stop                 # a reader holds the model mapped until this file exists in its container
LLM_MODEL=""                       # llm-model-fetch: the model on the host
LLM_BIN=""                         # llm-build: the engine on the host
LLM_WHERE=""                       # llm-where: the mappings of the model, a JSON list
LLM_LOG=""                         # llm-wait-holding: the log of the pod

llm-model-fetch() { # script API
    # Usage: llm-model-fetch
    #
    # Set LLM_MODEL to the model on the host: $llm_model if it is set (a
    # local copy), else $LLM_CACHE/$LLM_MODEL_FILE, downloaded from
    # $LLM_MODEL_URL if it is missing (the download goes into the cache
    # only with that sha256). Fail the test unless the file has sha256
    # $LLM_MODEL_SHA256.
    local model="${llm_model:-$LLM_CACHE/$LLM_MODEL_FILE}" part sum
    if [ -z "$llm_model" ] && [ ! -f "$model" ]; then
        mkdir -p "$LLM_CACHE" || error "llm-model-fetch: cannot create $LLM_CACHE"
        part="$model.part"
        # At most 30 min, and given up when slower than 1 MB/s for a minute.
        host-command "curl -fsSL --retry 3 --connect-timeout 30 --max-time 1800 --speed-limit 1048576 --speed-time 60 -o \"$part\" \"$LLM_MODEL_URL\"" || {
            rm -f "$part"
            error "llm-model-fetch: cannot download the model $LLM_MODEL_URL (proxy, network?). Download it by hand to $model, or set llm_model=PATH of a copy with sha256 $LLM_MODEL_SHA256"
        }
        sum=$(sha256sum "$part" | cut -d' ' -f1)
        if [ "$sum" != "$LLM_MODEL_SHA256" ]; then
            rm -f "$part"
            error "llm-model-fetch: the download of $LLM_MODEL_URL has sha256 $sum, expected $LLM_MODEL_SHA256"
        fi
        mv "$part" "$model" || error "llm-model-fetch: cannot move $part to $model"
    fi
    [ -f "$model" ] || error "llm-model-fetch: no model file llm_model=$model"
    if ! echo "$LLM_MODEL_SHA256  $model" | sha256sum --quiet -c; then
        [ -n "$llm_model" ] ||
            error "llm-model-fetch: $model does not have sha256 $LLM_MODEL_SHA256 of $LLM_MODEL_REPO $LLM_MODEL_FILE at $LLM_MODEL_COMMIT. Remove it to download it again"
        error "llm-model-fetch: llm_model=$model does not have sha256 $LLM_MODEL_SHA256 of $LLM_MODEL_REPO $LLM_MODEL_FILE at $LLM_MODEL_COMMIT"
    fi
    LLM_MODEL="$model"
    echo "llm-model-fetch: $LLM_MODEL, sha256 $LLM_MODEL_SHA256"
}

llm-build() { # script API
    # Usage: llm-build
    #
    # Build cxl-llm with cxl-llm/build.sh, or take the build of the same
    # sources from $LLM_CACHE, and set LLM_BIN to it. LLAMA_CPP_SRC in the
    # environment is a llama.cpp repository to take the pinned commit from
    # (see build.sh).
    local out
    out=$(CACHE_DIR="$(dirname "$LLM_CACHE")" "$LLM_HELPER_DIR/cxl-llm/build.sh") ||
        error "llm-build: cannot build cxl-llm, see above"
    [ -x "$out" ] || error "llm-build: build.sh printed no binary: $out"
    LLM_BIN="$out"
    echo "llm-build: $LLM_BIN, sha256 $(sha256sum "$LLM_BIN" | cut -d' ' -f1)"
}

llm-vm-put() {
    # Usage: llm-vm-put VMDIR SRC DST MODE
    #
    # Copy the host file SRC to DST in the VM of VMDIR, owned by root with
    # file mode MODE, unless DST has the same sha256 already.
    local vmdir="$1" src="$2" dst="$3" mode="$4" sum
    sum=$(sha256sum "$src" | cut -d' ' -f1)
    if [ "$(pool-vm-command-q "$vmdir" "sha256sum $dst 2>/dev/null" | cut -d' ' -f1)" == "$sum" ]; then
        echo "llm-vm-put: $(pool-vm-label "$vmdir"):$dst is up to date"
        return 0
    fi
    pool-vm-put-file "$vmdir" "$src" "$dst"
    pool-vm-command "$vmdir" "chown root:root $dst && chmod $mode $dst && sha256sum $dst" ||
        command-error "cannot install $dst in $(pool-vm-label "$vmdir")"
    [ "${COMMAND_OUTPUT%% *}" == "$sum" ] || error "llm-vm-put: $dst in $(pool-vm-label "$vmdir") is not a copy of $src"
}

llm-install() { # script API
    # Usage: llm-install VMDIR [model]
    #
    # Install the engine (llm-build) as $LLM_VM_BIN and cxl-where.py as
    # $LLM_VM_WHERE in the VM of VMDIR. With "model", install the model
    # (llm-model-fetch) as $LLM_VM_MODEL; without it, remove the model
    # from the VM, so that only the VM of the writer has it.
    local vmdir="$1" with_model="$2"
    [ -n "$LLM_BIN" ] || error "llm-install: run llm-build first"
    llm-vm-put "$vmdir" "$LLM_BIN" "$LLM_VM_BIN" 0555
    llm-vm-put "$vmdir" "$LLM_HELPER_DIR/cxl-where.py" "$LLM_VM_WHERE" 0555
    if [ "$with_model" == model ]; then
        [ -n "$LLM_MODEL" ] || error "llm-install: run llm-model-fetch first"
        llm-vm-put "$vmdir" "$LLM_MODEL" "$LLM_VM_MODEL" 0444
    else
        pool-vm-command "$vmdir" "rm -rf $LLM_VM_DIR/model; ls -la $LLM_VM_DIR" ||
            command-error "cannot remove the model from $(pool-vm-label "$vmdir")"
    fi
}

llm-pod-yaml() { # script API
    # Usage: llm-pod-yaml writer|reader NAME VMDIR CLAIM SCRIPT
    #
    # Print pod NAME on the node of VMDIR with ResourceClaim CLAIM, that
    # runs the shell SCRIPT and then idles until it is deleted
    # (dra-script-pod-yaml). A writer mounts $LLM_VM_DIR of the node, the
    # engine and the model; a reader mounts only the engine $LLM_VM_BIN.
    # Both read-only.
    local kind="$1" mount="File:$LLM_VM_BIN"
    [ "$kind" != writer ] || mount="Directory:$LLM_VM_DIR"
    dra-script-pod-yaml "$2" "$3" "$4" "$5" "$mount"
}

llm-reader-script() { # script API
    # Usage: llm-reader-script KEY THREADS
    #
    # Print the shell script of a reader container: show the environment of
    # device KEY and what the container has of $LLM_VM_DIR, try to open the
    # devdax device CXL_<KEY>_DAX for writing and to map it writable
    # (dax-rw.py check-ro of dra-dax-tool-install: "open for writing
    # refused: ERRNO", "writable mapping refused: ERRNO"), answer "hello"
    # with the model in the device on THREADS threads, and hold the model
    # mapped until $LLM_STOP exists. The last line it logs is "cxl-llm exit
    # STATUS".
    local key="$1" threads="$2"
    cat <<SCRIPT
env | grep ^CXL_${key}_ | sort
echo "$LLM_VM_DIR: \$(ls $LLM_VM_DIR | tr '\n' ' ')"
python3 /tools/dax-rw.py check-ro "\$CXL_${key}_DAX" 0
$LLM_VM_BIN -m "\$CXL_${key}_DAX" -t $threads -n 32 --hold $LLM_STOP hello
echo "cxl-llm exit \$?"
SCRIPT
}

llm-wait-holding() { # script API
    # Usage: llm-wait-holding VMDIR POD [TIMEOUT]
    #
    # Wait until the engine in pod POD has answered and holds the model
    # mapped, TIMEOUT seconds at most (default 180). Fail the test if it
    # exits before, or on timeout. LLM_LOG has the log of the pod then.
    local vmdir="$1" pod="$2" tmo="${3:-180}"
    retry-until --timeout "$tmo" --interval 1 --message "$pod: the engine answered and holds the model" \
        'LLM_LOG=$(dra-pod-log "$vmdir" "$pod") && grep -qE "^(cxl-llm: holding until .* exists|cxl-llm exit [0-9]+)$" <<< "$LLM_LOG"' || {
        dra-vm-command "$vmdir" "kubectl logs -n $DRA_NS $pod; kubectl describe pod -n $DRA_NS $pod | tail -n 20"
        error "the engine in pod $pod did not answer in ${tmo}s"
    }
    grep -qxF "cxl-llm: holding until $LLM_STOP exists" <<< "$LLM_LOG" || {
        echo "$LLM_LOG"
        error "the engine in pod $pod failed: $(grep '^cxl-llm exit ' <<< "$LLM_LOG")"
    }
}

llm-wait-exit() { # script API
    # Usage: llm-wait-exit VMDIR POD [TIMEOUT]
    #
    # Wait until the engine in pod POD has exited, TIMEOUT seconds at most
    # (default 120): its pod logs "cxl-llm exit STATUS". Fail the test on
    # timeout or unless STATUS is 0. LLM_LOG has the log of the pod then.
    local vmdir="$1" pod="$2" tmo="${3:-120}"
    retry-until --timeout "$tmo" --interval 1 --message "$pod: the engine exits" \
        'LLM_LOG=$(dra-pod-log "$vmdir" "$pod") && grep -qE "^cxl-llm exit [0-9]+$" <<< "$LLM_LOG"' || {
        dra-vm-command "$vmdir" "kubectl logs -n $DRA_NS $pod; kubectl describe pod -n $DRA_NS $pod | tail -n 20"
        error "the engine in pod $pod did not exit in ${tmo}s"
    }
    grep -qx "cxl-llm exit 0" <<< "$LLM_LOG" || {
        echo "$LLM_LOG"
        error "the engine in pod $pod failed: $(grep '^cxl-llm exit ' <<< "$LLM_LOG")"
    }
}

llm-log-answer() { # script API
    # Usage: llm-log-answer LOG
    #
    # Print the answer of the engine in LOG, the log of its pod (its line
    # "cxl-llm: answer: TEXT"). Return 1 if there is none.
    grep -m1 '^cxl-llm: answer: ' <<< "$1" | sed 's/^cxl-llm: answer: //' | grep .
}

llm-log-value() { # script API
    # Usage: llm-log-value LOG KEY
    #
    # Print the value of KEY (load_ms, gen_tps, ...) in the summary line of
    # the engine in LOG ("cxl-llm: source=... KEY=VALUE ..."). Return 1 if
    # there is none.
    grep -m1 '^cxl-llm: source=' <<< "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | grep .
}

llm-page-cache() { # script API
    # Usage: llm-page-cache VMDIR
    #
    # Print the page cache of the VM of VMDIR, the sum of FilePages of its
    # NUMA nodes, in kB, quietly.
    pool-vm-command-q "$1" "cat /sys/devices/system/node/node*/meminfo" | awk '$3 == "FilePages:" { kb += $4 } END { print kb + 0 }'
}

llm-engine-pid() { # script API
    # Usage: llm-engine-pid VMDIR POD
    #
    # Print the pid of the engine (comm cxl-llm) in container "main" of pod
    # POD in $DRA_NS, in the VM of VMDIR, quietly. Return 1 if it does not
    # run.
    local cg pid
    cg=$(dra-container-cgroup "$1" "$2" main) || return 1
    pid=$(pool-vm-command-q "$1" "for p in \$(cat $cg/cgroup.procs); do [ \"\$(cat /proc/\$p/comm 2>/dev/null)\" == cxl-llm ] && echo \$p; done")
    [ -n "$pid" ] || return 1
    echo "$pid"
}

llm-where() { # script API
    # Usage: llm-where VMDIR POD PATH
    #
    # Show where the page frames of the mappings of the file PATH (the
    # model as the engine sees it) of the engine in pod POD are, with
    # cxl-where.py in the VM of VMDIR. LLM_WHERE has them as a JSON list,
    # one object per mapping (see cxl-where.py).
    local vmdir="$1" pod="$2" path="$3" pid
    pid=$(llm-engine-pid "$vmdir" "$pod") || error "llm-where: no engine runs in pod $pod"
    pool-vm-command "$vmdir" "$LLM_VM_WHERE $pid $path" ||
        command-error "cxl-where.py failed on the engine of pod $pod"
    LLM_WHERE=$(python3 -c 'import json, sys; print(json.dumps([json.loads(l) for l in sys.stdin if l.startswith("{")]))' <<< "$COMMAND_OUTPUT")
}

llm-where-assert() { # script API
    # Usage: llm-where-assert VMDIR POD PATH SIZE CHAIN
    #
    # Fail the test unless the engine in pod POD (llm-where) has exactly
    # one mapping of the file PATH that is SIZE bytes long, every page of
    # it has a page frame, and the frames of all of them are in resources
    # of /proc/iomem whose chain (cxl-where.py "where", for instance "CXL
    # Window 0 > region0 > dax0.0") matches the Python regular expression
    # CHAIN. Other mappings of PATH are not counted.
    local vmdir="$1" pod="$2" path="$3" size="$4" chain="$5"
    llm-where "$vmdir" "$pod" "$path"
    python3 -c '
import json, re, sys
maps, size, chain = json.loads(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
model = [m for m in maps if m["size"] == size]
others = ", ".join("%d bytes, %d of %d pages present" % (m["size"], m["present"], m["pages"]) for m in maps if m["size"] != size)
print("mappings of the model: %s; not counted: %s" % (json.dumps(model), others or "none"))
if len(model) != 1:
    sys.exit("not one mapping of %d bytes" % size)
m = model[0]
bad = sorted(k for k in m["where"] if not re.search(chain, k))
if m["present"] != m["pages"] or bad:
    sys.exit("%d of %d pages present, frames outside %r: %s" % (m["present"], m["pages"], chain, bad))' "$LLM_WHERE" "$size" "$chain" ||
        error "the model mapping of the engine in pod $pod is not one mapping of $size bytes with all pages in '$chain'"
    echo "where ok: $pod: the $size-byte mapping of $path: every page present, all in '$chain'"
}

llm-file-sha256() { # script API
    # Usage: llm-file-sha256 FILE LENGTH
    #
    # Print the sha256 of the first LENGTH bytes of the host FILE, for
    # instance of the backing file of a device.
    head -c "$2" "$1" | sha256sum | cut -d' ' -f1
}

llm-file-zero() { # script API
    # Usage: llm-file-zero FILE OFFSET LENGTH
    #
    # Return 0 if the LENGTH bytes at OFFSET of the host FILE are all zero.
    python3 -c '
import sys
with open(sys.argv[1], "rb") as f:
    f.seek(int(sys.argv[2]))
    data = f.read(int(sys.argv[3]))
sys.exit(0 if len(data) == int(sys.argv[3]) and not data.strip(b"\0") else 1)' "$1" "$2" "$3"
}
