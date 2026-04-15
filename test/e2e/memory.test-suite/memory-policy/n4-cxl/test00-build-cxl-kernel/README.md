This test can be used for setting up a virtual machine (vagrant-managed Qemu) with:
- Linux kernel configured for CXL memory hotplugging and Kubernetes
- The latest released Kubernetes

Prerequisites:
- git, make, docker, vagrant, ansible
- qemu-system-x86, tested with 10.1.50 from github

After that, set up the virtual machine from scratch:

```
git clone -b 5er-pkg-cxl https://github.com/askervin/nri-plugins
cd nri-plugins
make PLUGINS=nri-memory-policy SKIP_LICENSES=1 OTHER_IMAGE_TARGETS="" images
cd test/e2e
kernel_getsource=v6.19 ./run_tests.sh memory.test-suite/memory-policy/n4-cxl/test00-build-cxl-kernel
```

To pause the test script (`code.var.sh`) at any point, add
`breakpoint` command. You can enter any function used in the script to
the interactive breakpoint prompt, for instance `vm-cxl-hotplug cxl_memdev0`.


Vagrant Qemus ssh servers listen to random host ports, and use
machine-specific private key for passwordless login. When
vagrant-managed Qemus are running, you can use the following script
(vagrant-ssh-hosts) to create and update
~/.ssh/config.d/vagrant-ssh-hosts file. It will make ssh/scp with the
Qemus convenient, simply: "ssh n4-cxl-fedora-43-containerd". Before
running the script, `mkdir ~/.ssh/config.d` and add `Include
~/.ssh/config.d/*` to your .ssh/config.

```
#!/bin/bash

vagrant_ssh_hosts_config=~/.ssh/config.d/vagrant-ssh-hosts

error() {
    echo "$*" >&2
    exit 1
}

[[ -d $(dirname "$vagrant_ssh_hosts_config") ]] || {
    error "Directory for $vagrant_ssh_hosts_config does not exist. Make sure to add Include for it in .ssh/config, too."
}

echo -n "" > "$vagrant_ssh_hosts_config"

for pid in $(pidof qemu-system-x86_64); do
    qemu_args=$(xargs -0 -n1 echo < /proc/$pid/cmdline)
    vm_name=""
    vm_ssh_port=""
    vm_ssh_key=""
    for arg in $qemu_args; do
        if grep -q .vagrant/machines <<< $arg; then
            # parse MACHINENAME from *.vagrant/machines/MACHINENAME/qemu/vq_k_TtfkhDhYw/linked-box.img
            vm_name=${arg##*.vagrant/machines/}
            vm_name=${vm_name%%/*}
            # parse PRIVATEKEY from
            vm_ssh_key=${arg##*file=}
            vm_ssh_key=${vm_ssh_key%/*/*.img}/private_key
            if ! [ -f $vm_ssh_key ]; then
                echo "could not find private key from $vm_ssh_key for vagrant machine $vm_name"
                continue
            fi
        elif grep -q -- hostfwd=.*-:22 <<< $arg; then
            # parse SSHPORT from user,id=net0,hostfwd=tcp::50903-:22,net=192.168.76.0/24,dhcpstart=192.168.76.9
            vm_ssh_port=${arg##*hostfwd=tcp::}
            vm_ssh_port=${vm_ssh_port%%-:22*}
        fi
    done
    if [[ -z "$vm_name" ]] || [[ -z "$vm_ssh_port" ]] || [[ -z "$vm_ssh_key" ]]; then
        echo "skipping qemu pid $pid"
        continue
    fi
    echo "found $vm_name"
    cat >> "$vagrant_ssh_hosts_config" <<EOF
Host $vm_name
    Hostname localhost
    User vagrant
    Port $vm_ssh_port
    IdentityFile $vm_ssh_key

EOF
done
```
