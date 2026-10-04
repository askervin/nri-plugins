#!/bin/bash
# Usage: vm-ssh.sh SSH_PORT COMMAND...   run COMMAND in a direct VM as user vagrant
# Usage: vm-ssh.sh SSH_PORT --wait [SECONDS]   wait until ssh works
KEY="${KEY:-/home/akervine/github.com/containers/nri-plugins/test/e2e/n4-cxl-fedora-43-containerd/.vagrant/machines/n4-cxl-fedora-43-containerd/qemu/private_key}"
port="$1"; shift
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes -p "$port" vagrant@127.0.0.1)
if [ "$1" = "--wait" ]; then
    tmo="${2:-300}"; t0=$SECONDS
    while ! timeout 10 "${SSH[@]}" true 2>/dev/null; do
        [ $((SECONDS - t0)) -ge "$tmo" ] && { echo "ssh to port $port: timeout ${tmo}s" >&2; exit 1; }
        sleep 3
    done
    echo "ssh to port $port ok after $((SECONDS - t0))s"
    exit 0
fi
exec "${SSH[@]}" "$@"
