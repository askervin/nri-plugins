# Helpers for running a small language model (LLM) from shared persistent
# CXL memory in the VMs of n4-cxl-shared-1 and n4-cxl-shared-2
# (test16-cxl-llm-share).
#
# The model is Qwen3-0.6B Q4_K_M, a GGUF file pinned by its Hugging Face
# commit and sha256, cached on the host in $CACHE_DIR/llm. The VM of the
# writer gets the model in $LLM_VM_MODEL_DIR and builds an erofs image of
# that directory, $LLM_VM_IMAGE, that a writer pod flashes into a
# persistent pool device. The readers are stock llama.cpp, the server image
# $LLM_SERVER_IMAGE, on the erofs that the driver mounts from the device.
# cxl-where.py shows whether the page frames of the model mapping of a
# reader are CXL memory or DRAM.
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
LLM_VM_MODEL_DIR="$LLM_VM_DIR/model"            # the model only: the root of the erofs image
LLM_VM_MODEL="$LLM_VM_MODEL_DIR/$LLM_MODEL_FILE"
LLM_VM_IMAGE="$LLM_VM_DIR/llm.erofs"            # the erofs image of $LLM_VM_MODEL_DIR
LLM_VM_STAMP="$LLM_VM_IMAGE.stamp"              # what the image was built from
# The file data of the model in one plain extent at a 2 MiB-aligned offset
# of the image: without -Enoinline_data the tail of the file is inline and
# the file silently gets no DAX.
LLM_MKFS="mkfs.erofs -b4096 --dsunit=512 -Enoinline_data"
LLM_VM_WHERE=/usr/local/bin/cxl-where.py
# Stock llama.cpp: entrypoint /app/llama-server, Ubuntu 24.04 with sh and
# curl, listens on 0.0.0.0:8080 (LLAMA_ARG_HOST, LLAMA_ARG_PORT).
LLM_SERVER_IMAGE=ghcr.io/ggml-org/llama.cpp:server-b11681
LLM_SERVER_PORT=8080
# Qwen3 thinks unless the think block is empty: the raw chat prompt of
# "hello" with an empty think block, answered greedily.
LLM_PROMPT='<|im_start|>user\nhello<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n'
LLM_MODEL=""                       # llm-model-fetch: the model on the host
LLM_IMAGE_SIZE=""                  # llm-image-build: the size of $LLM_VM_IMAGE in bytes
LLM_IMAGE_SHA256=""                # and its sha256
LLM_WHERE=""                       # llm-where: the mappings of the model, a JSON list
LLM_LOG=""                         # llm-server-wait, llm-writer-wait: the log of the pod
LLM_ANSWER=""                      # llm-ask: the response of the server, JSON,
LLM_CONTENT=""                     # and the completion in it

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

llm-kernel-require() { # script API
    # Usage: llm-kernel-require VMDIR TOPOLOGY
    #
    # Fail the test unless the running kernel of the VM of VMDIR, created
    # from TOPOLOGY, has CONFIG_EROFS_FS=y.
    local vmdir="$1" topology="$2"
    pool-vm-command "$vmdir" 'uname -r; grep -x CONFIG_EROFS_FS=y /boot/config-$(uname -r)' ||
        error "kernel of $(basename "$vmdir") lacks CONFIG_EROFS_FS=y: run memory.test-suite/dra-driver-cxl/$topology/test00-up: it installs the CXL kernel of test/e2e/playbook/files/qemu-cxl-kernel.config"
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
    pool-vm-command "$vmdir" "mkdir -p $(dirname "$dst")" || command-error "cannot create $(dirname "$dst") in $(pool-vm-label "$vmdir")"
    pool-vm-put-file "$vmdir" "$src" "$dst"
    pool-vm-command "$vmdir" "chown root:root $dst && chmod $mode $dst && sha256sum $dst" ||
        command-error "cannot install $dst in $(pool-vm-label "$vmdir")"
    [ "${COMMAND_OUTPUT%% *}" == "$sum" ] || error "llm-vm-put: $dst in $(pool-vm-label "$vmdir") is not a copy of $src"
}

llm-install() { # script API
    # Usage: llm-install VMDIR [model]
    #
    # Install cxl-where.py as $LLM_VM_WHERE in the VM of VMDIR. With
    # "model", make $LLM_VM_MODEL_DIR hold the model (llm-model-fetch) and
    # nothing else, and $LLM_VM_DIR nothing but it and the erofs image;
    # without it, empty $LLM_VM_DIR.
    local vmdir="$1" with_model="$2"
    llm-vm-put "$vmdir" "$LLM_HELPER_DIR/cxl-where.py" "$LLM_VM_WHERE" 0555
    if [ "$with_model" == model ]; then
        [ -n "$LLM_MODEL" ] || error "llm-install: run llm-model-fetch first"
        llm-vm-put "$vmdir" "$LLM_MODEL" "$LLM_VM_MODEL" 0444
        pool-vm-command "$vmdir" "find $LLM_VM_MODEL_DIR -mindepth 1 ! -path $LLM_VM_MODEL -delete; find $LLM_VM_DIR -mindepth 1 -maxdepth 1 ! -path $LLM_VM_MODEL_DIR ! -path $LLM_VM_IMAGE ! -path $LLM_VM_STAMP -exec rm -rf {} +; ls -la $LLM_VM_DIR $LLM_VM_MODEL_DIR" ||
            command-error "cannot clean up $LLM_VM_DIR in $(pool-vm-label "$vmdir")"
    else
        pool-vm-command "$vmdir" "rm -rf $LLM_VM_DIR && mkdir -p $LLM_VM_DIR && ls -la $LLM_VM_DIR" ||
            command-error "cannot remove the model from $(pool-vm-label "$vmdir")"
    fi
}

llm-image-build() { # script API
    # Usage: llm-image-build VMDIR
    #
    # Make $LLM_VM_IMAGE in the VM of VMDIR an erofs image of
    # $LLM_VM_MODEL_DIR (llm-install VMDIR model), built with
    # "$LLM_MKFS IMAGE DIR". Reuse the image if its stamp names the sha256
    # of the model and that command. Install erofs-utils if mkfs.erofs is
    # missing. Fail the test unless dump.erofs shows the model as one plain
    # extent (layout 0) at a 2 MiB-aligned offset of the image. Set
    # LLM_IMAGE_SIZE and LLM_IMAGE_SHA256.
    local vmdir="$1" label stamp out
    label=$(pool-vm-label "$vmdir")
    stamp="model sha256 $LLM_MODEL_SHA256, $LLM_MKFS"
    pool-vm-command-q "$vmdir" "command -v mkfs.erofs >/dev/null && command -v dump.erofs >/dev/null" ||
        pool-vm-command "$vmdir" "dnf install -y erofs-utils" ||
            command-error "cannot install erofs-utils in $label"
    pool-vm-command "$vmdir" "mkfs.erofs --version | head -n 1" || command-error "no mkfs.erofs in $label"
    if [ "$(pool-vm-command-q "$vmdir" "cat $LLM_VM_STAMP 2>/dev/null && test -f $LLM_VM_IMAGE")" == "$stamp" ]; then
        echo "llm-image-build: $label:$LLM_VM_IMAGE is up to date ($stamp)"
    else
        pool-vm-command "$vmdir" "rm -f $LLM_VM_STAMP $LLM_VM_IMAGE && $LLM_MKFS $LLM_VM_IMAGE $LLM_VM_MODEL_DIR && echo '$stamp' > $LLM_VM_STAMP" ||
            command-error "cannot build the erofs image $LLM_VM_IMAGE in $label"
    fi
    pool-vm-command "$vmdir" "dump.erofs -e --path=/$LLM_MODEL_FILE $LLM_VM_IMAGE" ||
        command-error "dump.erofs cannot show /$LLM_MODEL_FILE in $LLM_VM_IMAGE"
    out="$COMMAND_OUTPUT"
    # The extent line: "   0:        0..396705792 | 396705792 :    2097152.. 398802944 | 396705792".
    python3 -c '
import re, sys
text, size = sys.argv[1], int(sys.argv[2])
layout = re.search(r"\bLayout: (\d+)\b", text)
exts = re.findall(r"^\s*\d+:\s*(\d+)\.\.\s*(\d+)\s*\|\s*(\d+)\s*:\s*(\d+)\.\.\s*(\d+)\s*\|\s*(\d+)\s*$", text, re.M)
if not layout or layout.group(1) != "0":
    sys.exit("the model has layout %s, not 0 (plain): its tail is inline, the file gets no DAX" % (layout.group(1) if layout else "?"))
if len(exts) != 1 or int(exts[0][0]) != 0 or int(exts[0][1]) < size:
    sys.exit("the model is not one extent of %d bytes: %s" % (size, exts))
if int(exts[0][3]) % (2 << 20):
    sys.exit("the model starts at %s of the image, not at a 2 MiB-aligned offset" % exts[0][3])
print("the model: one plain extent at offset %s of the image" % exts[0][3])' "$out" "$LLM_MODEL_SIZE" ||
        error "llm-image-build: $LLM_VM_IMAGE does not have the model in one plain 2 MiB-aligned extent"
    pool-vm-command "$vmdir" "stat -c %s $LLM_VM_IMAGE && sha256sum $LLM_VM_IMAGE" ||
        command-error "cannot read $LLM_VM_IMAGE in $label"
    LLM_IMAGE_SIZE=$(head -n 1 <<< "$COMMAND_OUTPUT")
    LLM_IMAGE_SHA256=$(sed -n '2s/ .*//p' <<< "$COMMAND_OUTPUT")
    [ -n "$LLM_IMAGE_SIZE" ] && [ -n "$LLM_IMAGE_SHA256" ] || error "llm-image-build: no size and sha256 of $LLM_VM_IMAGE"
    echo "llm-image-build: $label:$LLM_VM_IMAGE, $LLM_IMAGE_SIZE bytes, sha256 $LLM_IMAGE_SHA256"
}

llm-writer-script() { # script API
    # Usage: llm-writer-script KEY
    #
    # Print the shell script of a writer container (image $DRA_TOOLS_IMAGE,
    # $LLM_VM_IMAGE mounted from the node) with the block device of device
    # KEY: show the environment of the device, check that the image fits
    # in CXL_<KEY>_SIZE, write the image with dd into CXL_<KEY>_PATH and
    # print the sha256 of as many bytes of the device as the image has
    # ("device sha256: SUM"). The last line it logs is "writer exit
    # STATUS".
    local key="$1"
    cat <<SCRIPT
env | grep ^CXL_${key}_ | sort
dev="\$CXL_${key}_PATH"
size="\$CXL_${key}_SIZE"
img=$LLM_VM_IMAGE
bytes=\$(stat -c %s "\$img")
ls -l "\$dev"
if [ -b "\$dev" ]; then echo "block device: \$dev"; else echo "not a block device: \$dev"; fi
echo "image \$img: \$bytes bytes, device \$dev: \$size bytes"
if [ "\$bytes" -gt "\$size" ]; then
    echo "the image does not fit into the device"
    echo "writer exit 2"
else
    t0=\$(python3 -c 'import time; print(time.time())')
    dd if="\$img" of="\$dev" bs=2M conv=fsync
    rc=\$?
    t1=\$(python3 -c 'import time; print(time.time())')
    echo "dd exit \$rc in \$(python3 -c "print(round((\$t1 - \$t0) * 1000))") ms"
    echo "device sha256: \$(head -c "\$bytes" "\$dev" | sha256sum | cut -d' ' -f1)"
    echo "writer exit \$rc"
fi
SCRIPT
}

llm-writer-wait() { # script API
    # Usage: llm-writer-wait VMDIR POD [TIMEOUT]
    #
    # Wait until the writer in pod POD logs "writer exit STATUS", TIMEOUT
    # seconds at most (default 180). Fail the test on timeout or unless
    # STATUS is 0. LLM_LOG has the log of the pod then.
    local vmdir="$1" pod="$2" tmo="${3:-180}"
    retry-until --timeout "$tmo" --interval 1 --message "$pod: the writer exits" \
        'LLM_LOG=$(dra-pod-log "$vmdir" "$pod") && grep -qE "^writer exit [0-9]+$" <<< "$LLM_LOG"' || {
        dra-vm-command "$vmdir" "kubectl logs -n $DRA_NS $pod; kubectl describe pod -n $DRA_NS $pod | tail -n 20"
        error "the writer in pod $pod did not exit in ${tmo}s"
    }
    grep -qx "writer exit 0" <<< "$LLM_LOG" || {
        echo "$LLM_LOG"
        error "the writer in pod $pod failed: $(grep '^writer exit ' <<< "$LLM_LOG")"
    }
}

llm-reader-script() { # script API
    # Usage: llm-reader-script KEY THREADS
    #
    # Print the shell script of a reader container (image
    # $LLM_SERVER_IMAGE) with the erofs of device KEY at CXL_<KEY>_PATH:
    # show the environment of the device, its mount in the container and
    # the files in it, whether the container has pmem devices ("no pmem
    # devices" or "pmem devices: ..."), try to create a file under the
    # mount ("write under PATH refused: ERROR" or "write under PATH: done"),
    # then run llama-server on THREADS threads with the model mapped from
    # the mount, without repacking the weights, on port $LLM_SERVER_PORT.
    local key="$1" threads="$2"
    cat <<SCRIPT
env | grep ^CXL_${key}_ | sort
p="\$CXL_${key}_PATH"
echo "mount: \$(grep " \$p " /proc/self/mountinfo)"
echo "files: \$(ls "\$p" | tr '\n' ' ')"
if ls /dev/pmem* >/dev/null 2>&1; then echo "pmem devices: \$(echo /dev/pmem*)"; else echo "no pmem devices"; fi
if out=\$(touch "\$p/probe" 2>&1); then echo "write under \$p: done"; else echo "write under \$p refused: \$out"; fi
exec /app/llama-server -m "\$p/$LLM_MODEL_FILE" -nr -t $threads -c 512 -np 1 --host 0.0.0.0 --port $LLM_SERVER_PORT
SCRIPT
}

# shellcheck disable=SC2001 # sed indents every line of SCRIPT
llm-server-pod-yaml() { # script API
    # Usage: llm-server-pod-yaml NAME VMDIR CLAIM SCRIPT
    #
    # Print pod NAME on the node of VMDIR, restartPolicy Never, running the
    # shell SCRIPT in its container "main" of $LLM_SERVER_IMAGE, with
    # ResourceClaim CLAIM as its claim "mem" ("": no claim).
    local name="$1" node claim="$3" script="$4" claims="" uses=""
    node=$(basename "$2")
    if [ -n "$claim" ]; then
        claims="
  resourceClaims:
  - name: mem
    resourceClaimName: $claim"
        uses="
    resources:
      claims:
      - name: mem"
    fi
    cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  nodeSelector:
    kubernetes.io/hostname: $node
  terminationGracePeriodSeconds: 2
  restartPolicy: Never$claims
  containers:
  - name: main
    image: $LLM_SERVER_IMAGE
    imagePullPolicy: IfNotPresent
    command:
    - sh
    - -c
    - |
$(sed 's/^/      /' <<< "$script")
    ports:
    - containerPort: $LLM_SERVER_PORT$uses
EOF
}

llm-warm() { # script API
    # Usage: llm-warm VMDIR
    #
    # Read the files of /app of $LLM_SERVER_IMAGE and the libraries of
    # llama-server once on the node of VMDIR into its page cache, in pod
    # llm-warm without a claim.
    local vmdir="$1"
    dra-apply "$OUTPUT_DIR" <<< "$(llm-server-pod-yaml llm-warm "$vmdir" "" "cat \$(find /app -type f) \$(ldd /app/llama-server /app/*.so 2>/dev/null | awk '\$3 ~ /^\\// {print \$3}' | sort -u) >/dev/null 2>&1; echo \"warm: \$(du -sh /app | cut -f1) of /app and the libraries of llama-server read\"")"
    dra-pod-wait "$OUTPUT_DIR" llm-warm Succeeded 120
    dra-pod-log "$OUTPUT_DIR" llm-warm
    dra-delete-pod "$OUTPUT_DIR" llm-warm
}

llm-pod-ip() { # script API
    # Usage: llm-pod-ip POD
    #
    # Print the IP address of pod POD in $DRA_NS, quietly. Return 1 if it
    # has none.
    local ip
    ip=$(dra-vm-command-q "$OUTPUT_DIR" "kubectl get pod -n $DRA_NS $1 -o jsonpath={.status.podIP}")
    [ -n "$ip" ] || return 1
    echo "$ip"
}

llm-server-ready() {
    # Usage: llm-server-ready VMDIR POD
    #
    # Return 0 if llama-server in pod POD answers /health with 200 on its
    # pod IP, asked from the VM of VMDIR. Return 2 if the pod has
    # terminated.
    local vmdir="$1" pod="$2" ip phase
    phase=$(dra-vm-command-q "$OUTPUT_DIR" "kubectl get pod -n $DRA_NS $pod -o jsonpath={.status.phase}")
    case "$phase" in Succeeded|Failed) return 2;; esac
    ip=$(llm-pod-ip "$pod") || return 1
    [ "$(dra-vm-command-q "$vmdir" "curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://$ip:$LLM_SERVER_PORT/health")" == 200 ]
}

llm-server-wait() { # script API
    # Usage: llm-server-wait VMDIR POD [TIMEOUT]
    #
    # Wait until llama-server in pod POD has loaded the model and serves
    # (llm-server-ready from the VM of VMDIR, the node of the pod), TIMEOUT
    # seconds at most (default 180). Fail the test if the pod terminates
    # before, or on timeout. LLM_LOG has the log of the pod then.
    local vmdir="$1" pod="$2" tmo="${3:-180}" rc=0
    retry-until --timeout "$tmo" --interval 1 --message "$pod: llama-server serves" \
        'llm-server-ready "$vmdir" "$pod"; rc=$?; [ "$rc" == 0 ] || [ "$rc" == 2 ]' || rc=1
    LLM_LOG=$(dra-pod-log "$OUTPUT_DIR" "$pod")
    if [ "$rc" != 0 ]; then
        echo "$LLM_LOG"
        dra-vm-command "$OUTPUT_DIR" "kubectl describe pod -n $DRA_NS $pod | tail -n 20"
        [ "$rc" == 2 ] && error "llama-server in pod $pod terminated before it served"
        error "llama-server in pod $pod did not serve in ${tmo}s"
    fi
}

llm-ask() { # script API
    # Usage: llm-ask VMDIR POD
    #
    # Ask llama-server in pod POD, from the VM of VMDIR (the node of the
    # pod), on its pod IP, for the greedy completion (temperature 0, top_k
    # 1) of $LLM_PROMPT in 32 tokens at most. LLM_ANSWER has the response
    # of the server, LLM_CONTENT the completion without surrounding white
    # space. Fail the test if there is none.
    local vmdir="$1" pod="$2" ip
    ip=$(llm-pod-ip "$pod") || error "llm-ask: pod $pod has no IP"
    pool-vm-command "$vmdir" "curl -sS --max-time 120 -H 'Content-Type: application/json' http://$ip:$LLM_SERVER_PORT/completion -d @- <<'LLM_ASK_EOF'
{\"prompt\": \"$LLM_PROMPT\", \"n_predict\": 32, \"temperature\": 0, \"top_k\": 1}
LLM_ASK_EOF" || command-error "llm-ask: no response of llama-server in pod $pod"
    LLM_ANSWER="$COMMAND_OUTPUT"
    LLM_CONTENT=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["content"].strip())' "$LLM_ANSWER") ||
        error "llm-ask: llama-server in pod $pod gave no completion: $LLM_ANSWER"
    echo "llm-ask: $pod answered: $LLM_CONTENT"
}

llm-answer-value() { # script API
    # Usage: llm-answer-value EXPRESSION
    #
    # Print the value of the Python EXPRESSION on the last response of
    # llm-ask, j, for instance j["timings"]["predicted_per_second"].
    pool-value "$LLM_ANSWER" "$1"
}

llm-page-cache() { # script API
    # Usage: llm-page-cache VMDIR
    #
    # Print the page cache of the VM of VMDIR, the sum of FilePages of its
    # NUMA nodes, in kB, quietly.
    pool-vm-command-q "$1" "cat /sys/devices/system/node/node*/meminfo" | awk '$3 == "FilePages:" { kb += $4 } END { print kb + 0 }'
}

llm-pod-file() { # script API
    # Usage: llm-pod-file VMDIR POD
    #
    # Print the page cache charged to the cgroup of pod POD in $DRA_NS (the
    # parent of the cgroup of its container "main"), in bytes ("file" of
    # its memory.stat), quietly. Return 1 if there is no such cgroup.
    local cg bytes
    cg=$(dra-container-cgroup "$1" "$2" main) || return 1
    bytes=$(pool-vm-command-q "$1" "awk '\$1 == \"file\" {print \$2}' $(dirname "$cg")/memory.stat")
    [ -n "$bytes" ] || return 1
    echo "$bytes"
}

llm-file-charges() { # script API
    # Usage: llm-file-charges VMDIR
    #
    # Print the page cache charged to the cgroups of the VM of VMDIR down
    # to the pods of Kubernetes, one "kB CGROUP" per line ("file" of
    # memory.stat), quietly.
    pool-vm-command-q "$1" "for f in /sys/fs/cgroup/*/memory.stat /sys/fs/cgroup/*/*/memory.stat /sys/fs/cgroup/kubepods.slice/*/*/memory.stat; do [ -f \"\$f\" ] && echo \"\$(( \$(awk '\$1 == \"file\" {print \$2}' \"\$f\") / 1024 )) \${f%/memory.stat}\"; done"
}

llm-file-charges-delta() { # script API
    # Usage: llm-file-charges-delta BEFORE AFTER
    #
    # Print the cgroups whose page cache grew from BEFORE to AFTER (outputs
    # of llm-file-charges), the five largest growths, "+kB CGROUP" each.
    python3 -c '
import sys
def parse(text):
    return {c: int(k) for k, c in (l.split(None, 1) for l in text.splitlines() if l.strip())}
b, a = parse(sys.argv[1]), parse(sys.argv[2])
grown = sorted(((a[c] - b.get(c, 0), c) for c in a if a[c] > b.get(c, 0)), reverse=True)[:5]
print(", ".join("+%d kB %s" % g for g in grown) or "none")' "$1" "$2"
}

llm-server-pid() { # script API
    # Usage: llm-server-pid VMDIR POD
    #
    # Print the pid of llama-server (comm llama-server) in container "main"
    # of pod POD in $DRA_NS, in the VM of VMDIR, quietly. Return 1 if it
    # does not run.
    local cg pid
    cg=$(dra-container-cgroup "$1" "$2" main) || return 1
    pid=$(pool-vm-command-q "$1" "for p in \$(cat $cg/cgroup.procs); do [ \"\$(cat /proc/\$p/comm 2>/dev/null)\" == llama-server ] && echo \$p; done")
    [ -n "$pid" ] || return 1
    echo "$pid"
}

llm-rss-anon() { # script API
    # Usage: llm-rss-anon VMDIR POD
    #
    # Print RssAnon of llama-server in pod POD, in kB, quietly. Return 1 if
    # it does not run.
    local pid
    pid=$(llm-server-pid "$1" "$2") || return 1
    pool-vm-command-q "$1" "awk '\$1 == \"RssAnon:\" {print \$2}' /proc/$pid/status"
}

llm-where() { # script API
    # Usage: llm-where VMDIR POD PATH
    #
    # Show where the page frames of the mappings of the file PATH (the
    # model as the server sees it) of llama-server in pod POD are, with
    # cxl-where.py in the VM of VMDIR. LLM_WHERE has them as a JSON list,
    # one object per mapping (see cxl-where.py).
    local vmdir="$1" pod="$2" path="$3" pid
    pid=$(llm-server-pid "$vmdir" "$pod") || error "llm-where: no llama-server runs in pod $pod"
    pool-vm-command "$vmdir" "$LLM_VM_WHERE $pid $path" ||
        command-error "cxl-where.py failed on llama-server of pod $pod"
    LLM_WHERE=$(python3 -c 'import json, sys; print(json.dumps([json.loads(l) for l in sys.stdin if l.startswith("{")]))' <<< "$COMMAND_OUTPUT")
}

llm-where-assert() { # script API
    # Usage: llm-where-assert VMDIR POD PATH MIN-BYTES CHAIN
    #
    # Fail the test unless llama-server in pod POD (llm-where) maps the
    # file PATH with MIN-BYTES bytes at least in all, every page of its
    # mappings of PATH has a page frame, and the frames of all of them are
    # in resources of /proc/iomem whose chain (cxl-where.py "where", for
    # instance "CXL Window 0 > Persistent Memory > region0 >
    # namespace0.0") matches the Python regular expression CHAIN.
    local vmdir="$1" pod="$2" path="$3" min="$4" chain="$5"
    llm-where "$vmdir" "$pod" "$path"
    python3 -c '
import json, re, sys
maps, least, chain = json.loads(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
print("mappings of the model: %s" % json.dumps(maps))
size = sum(m["size"] for m in maps)
if size < least:
    sys.exit("%d bytes mapped, less than %d" % (size, least))
for m in maps:
    bad = sorted(k for k in m["where"] if not re.search(chain, k))
    if m["present"] != m["pages"] or bad:
        sys.exit("mapping at %s: %d of %d pages present, frames outside %r: %s" % (m["start"], m["present"], m["pages"], chain, bad))' "$LLM_WHERE" "$min" "$chain" ||
        error "the model mappings of llama-server in pod $pod are not $min bytes at least with all pages in '$chain'"
    echo "where ok: $pod: the mappings of $path: $(python3 -c 'import json, sys; m = json.loads(sys.argv[1]); print("%d bytes, %d pages" % (sum(x["size"] for x in m), sum(x["pages"] for x in m)))' "$LLM_WHERE"), every page present, all in '$chain'"
}

llm-file-sha256() { # script API
    # Usage: llm-file-sha256 FILE [LENGTH]
    #
    # Print the sha256 of the host FILE, or of its first LENGTH bytes, for
    # instance of the backing file of a device.
    if [ -n "$2" ]; then
        head -c "$2" "$1" | sha256sum | cut -d' ' -f1
    else
        sha256sum "$1" | cut -d' ' -f1
    fi
}

llm-file-zero() { # script API
    # Usage: llm-file-zero FILE OFFSET LENGTH
    #
    # Return 0 if the LENGTH bytes at OFFSET of the host FILE are all zero.
    python3 -c '
import sys
with open(sys.argv[1], "rb") as f:
    f.seek(int(sys.argv[2]))
    left = int(sys.argv[3])
    while left:
        data = f.read(min(left, 1 << 22))
        if not data or data.strip(b"\0"):
            sys.exit(1)
        left -= len(data)' "$1" "$2" "$3"
}

llm-file-find() { # script API
    # Usage: llm-file-find FILE MODEL ALIGN
    #
    # Print the first offset of the host FILE, a multiple of ALIGN, at
    # which the bytes of the host file MODEL are, compared by sha256.
    # Return 1 if there is none.
    python3 -c '
import hashlib, os, sys
path, model, align = sys.argv[1], sys.argv[2], int(sys.argv[3])
size = os.path.getsize(model)
with open(model, "rb") as f:
    head = f.read(1 << 16)
    want = hashlib.sha256(head + f.read()).hexdigest()
with open(path, "rb") as f:
    end = os.path.getsize(path) - size
    for off in range(0, end + 1, align):
        f.seek(off)
        if f.read(len(head)) != head:
            continue
        h = hashlib.sha256(head)
        left = size - len(head)
        while left:
            data = f.read(min(left, 1 << 22))
            if not data:
                break
            h.update(data)
            left -= len(data)
        if h.hexdigest() == want:
            print(off)
            sys.exit(0)
sys.exit(1)' "$1" "$2" "$3"
}
