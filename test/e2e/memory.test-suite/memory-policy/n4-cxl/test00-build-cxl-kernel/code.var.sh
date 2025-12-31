breakpoint
vm-kernel-pkgs-install

vm-cxl-hotplug cxl_memdev0

# Install utilities
vm-command "command -v cxl || dnf install -y /usr/bin/cxl numactl golang"

vm-command "mkdir udev-monitor 2>/dev/null" && {
    udev_monitor_tool="${TEST_DIR%%/test/e2e/*}/scripts/udev-monitor/udev-monitor.go"
    vm-put-file "$udev_monitor_tool" "./udev-monitor/udev-monitor.go"
    vm-command "go version | grep 1.25 || {
       curl -OL https://go.dev/dl/go1.25.5.linux-amd64.tar.gz && \
       tar xvf go1.25.5.linux-amd64.tar.gz -C /usr/local
       echo 'export PATH=/usr/local/go/bin:\$PATH' > /etc/profile.d/z99-usr-local-go.sh
    }"
    vm-command "cd udev-monitor && go mod init udev-monitor && go mod tidy && go build . && cp -v udev-monitor /usr/local/bin"
}

vm-command 'cat > usemem.c <<EOF
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <numaif.h>

#define BLOCK_SIZE (2UL * 1024 * 1024)
#define NUM_BLOCKS 4
#define CXL_NODE   2   /* adjust to your CXL NUMA node */

static void pause_here(const char *msg)
{
    fprintf(stderr, "\n--- %s ---\n", msg);
    fprintf(stderr, "PID %d paused. Press Enter to continue...\n", getpid());
    fflush(stderr);
    getchar();
}

int main(void)
{
    size_t size = NUM_BLOCKS * BLOCK_SIZE;
    void *buf;

    fprintf(stderr,
            "Requesting %zu bytes (%d × 2MB huge pages)\n",
            size, NUM_BLOCKS);

    /*
     * Allocate anonymous memory backed by explicit 2MB huge pages
     * This guarantees page size.
     */
    buf = mmap(NULL,
               size,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
               -1,
               0);

    if (buf == MAP_FAILED) {
        perror("mmap(MAP_HUGETLB)");
        return 1;
    }

    fprintf(stderr, "Mapped virtual address: %p\n", buf);
    pause_here("After mmap (no pages faulted yet)");

    /*
     * Bind mapping to CXL NUMA node
     */
    unsigned long nodemask = 1UL << CXL_NODE;

    fprintf(stderr, "Binding mapping to NUMA node %d (CXL)\n", CXL_NODE);

    if (mbind(buf, size,
              MPOL_BIND,
              &nodemask,
              sizeof(nodemask) * 8,
              0) != 0) {
        perror("mbind");
        return 1;
    }

    pause_here("After mbind (still no physical pages)");

    /*
     * Fault pages in — allocation happens here
     * One write per 2MB page is sufficient
     * Note: write exactly on 2MB aligned addresses works fine.
     */
    fprintf(stderr, "Faulting pages in (touching each 2MB block)...\n");

    for (size_t off = 0; off < size; off += BLOCK_SIZE) {
        volatile char *p = (char *)buf + off;
        fprintf(stderr, "Write address %lx, byte: 0x0\n", (buf+off));
        *p = 0;
    }

    pause_here("After first touch (pages allocated on CXL)");

    /*
     * Use memory normally
     */
    // fprintf(stderr, "Writing test pattern...\n");
    // memset(buf, 0xAB, size);
    fprintf(stderr, "Writing test pattern...\n");
    for (size_t off = 0; off < size; off += BLOCK_SIZE) {
        volatile long int *p = (long int *)(buf + off);
        long int v = 0xDEADBEEFD00D0C81;
        fprintf(stderr, "Write address %lx, value: %lx\n", (buf+off), v);
        *p = v;
    }

    /* this causes illegal instruction in qemu/kvm: memset(buf, 0xAB, size); */

    pause_here("After writing data");
    fprintf(stderr, "Reading test pattern...\n");
    for (size_t off = 0; off < size; off += BLOCK_SIZE) {
        volatile long int *p = (long int *)(buf + off);
        fprintf(stderr, "Read address %lx, value: %lx\n", (buf+off), *p);
    }

    pause_here("After writing data");

    fprintf(stderr, "Cleaning up and exiting.\n");
    munmap(buf, size);

    return 0;
}
EOF
# gcc -o usemem usemem.c -lnuma && ./usemem
'

# Note:
#
# To prevent using instructions where accessing the memory fails, mark all memory
# on nodes as huge pages.
# echo 128 > /sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages
#
# writing test pattern works fine even when writing to char* on every byte address (off+=1)

# [root@n4-cxl-fedora-42-containerd fleshutils]# ls -l /sys/bus/cxl/devices/
# dax_region0 -> ../../../devices/platform/ACPI0017:00/root0/decoder0.0/region0/dax_region0
# dax_region1 -> ../../../devices/platform/ACPI0017:00/root0/decoder0.1/region1/dax_region1
# decoder0.0 -> ../../../devices/platform/ACPI0017:00/root0/decoder0.0
# decoder0.1 -> ../../../devices/platform/ACPI0017:00/root0/decoder0.1
# decoder1.0 -> ../../../devices/platform/ACPI0017:00/root0/port1/decoder1.0
# decoder2.0 -> ../../../devices/platform/ACPI0017:00/root0/port2/decoder2.0
# decoder3.0 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/decoder3.0
# decoder3.1 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/decoder3.1
# decoder3.2 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/decoder3.2
# decoder3.3 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/decoder3.3
# decoder4.0 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.0
# decoder4.1 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.1
# decoder4.2 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.2
# decoder4.3 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint4/decoder4.3
# decoder5.0 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/decoder5.0
# decoder5.1 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/decoder5.1
# decoder5.2 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/decoder5.2
# decoder5.3 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/decoder5.3
# decoder6.0 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/endpoint6/decoder6.0
# decoder6.1 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/endpoint6/decoder6.1
# decoder6.2 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/endpoint6/decoder6.2
# decoder6.3 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/endpoint6/decoder6.3
# decoder7.0 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint7/decoder7.0
# decoder7.1 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint7/decoder7.1
# decoder7.2 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint7/decoder7.2
# decoder7.3 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint7/decoder7.3
# endpoint4 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint4
# endpoint6 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5/endpoint6
# endpoint7 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3/endpoint7
# mem0 -> ../../../devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:00.0/0000:0f:00.0/mem0
# mem1 -> ../../../devices/pci0000:18/0000:18:00.0/0000:19:00.0/0000:1a:01.0/0000:1c:00.0/mem1
# mem2 -> ../../../devices/pci0000:0c/0000:0c:00.0/0000:0d:00.0/0000:0e:01.0/0000:10:00.0/mem2
# nvdimm-bridge0 -> ../../../devices/platform/ACPI0017:00/root0/nvdimm-bridge0
# port1 -> ../../../devices/platform/ACPI0017:00/root0/port1
# port2 -> ../../../devices/platform/ACPI0017:00/root0/port2
# port3 -> ../../../devices/platform/ACPI0017:00/root0/port2/port3
# port5 -> ../../../devices/platform/ACPI0017:00/root0/port1/port5
# region0 -> ../../../devices/platform/ACPI0017:00/root0/decoder0.0/region0
# region1 -> ../../../devices/platform/ACPI0017:00/root0/decoder0.1/region1
# root0 -> ../../../devices/platform/ACPI0017:00/root0


# [root@n4-cxl-fedora-42-containerd fleshutils]# grep -sr . /sys/bus/cxl/devices/mem0
# /sys/bus/cxl/devices/mem0/uevent:MAJOR=251
# /sys/bus/cxl/devices/mem0/uevent:MINOR=0
# /sys/bus/cxl/devices/mem0/uevent:DEVNAME=cxl/mem0
# /sys/bus/cxl/devices/mem0/uevent:DEVTYPE=cxl_memdev
# /sys/bus/cxl/devices/mem0/uevent:DRIVER=cxl_mem
# /sys/bus/cxl/devices/mem0/uevent:MODALIAS=cxl:t5
# /sys/bus/cxl/devices/mem0/label_storage_size:0
# /sys/bus/cxl/devices/mem0/pmem/size:0x0
# /sys/bus/cxl/devices/mem0/firmware_version:BWFW VERSION 00
# /sys/bus/cxl/devices/mem0/numa_node:0
# /sys/bus/cxl/devices/mem0/dev:251:0
# /sys/bus/cxl/devices/mem0/ram/size:0x10000000
# /sys/bus/cxl/devices/mem0/security/state:disabled
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_active_time:0
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_active_kids:0
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_usage:0
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_status:unsupported
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_suspended_time:0
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/runtime_enabled:disabled
# /sys/bus/cxl/devices/mem0/firmware/mem0/power/control:auto
# /sys/bus/cxl/devices/mem0/firmware/mem0/loading:0
# /sys/bus/cxl/devices/mem0/firmware/mem0/status:idle
# /sys/bus/cxl/devices/mem0/firmware/mem0/remaining_size:0
# /sys/bus/cxl/devices/mem0/serial:0xc100e2e0
# /sys/bus/cxl/devices/mem0/payload_max:2048

# [root@n4-cxl-fedora-42-containerd fleshutils]# grep -sr . /sys/bus/cxl/devices/dax_region0/
# /sys/bus/cxl/devices/dax_region0/uevent:DEVTYPE=cxl_dax_region
# /sys/bus/cxl/devices/dax_region0/uevent:DRIVER=cxl_dax_region
# /sys/bus/cxl/devices/dax_region0/uevent:MODALIAS=cxl:t8
# /sys/bus/cxl/devices/dax_region0/dax0.0/uevent:MAJOR=252
# /sys/bus/cxl/devices/dax_region0/dax0.0/uevent:MINOR=0
# /sys/bus/cxl/devices/dax_region0/dax0.0/uevent:DEVNAME=dax0.0
# /sys/bus/cxl/devices/dax_region0/dax0.0/uevent:DRIVER=kmem
# /sys/bus/cxl/devices/dax_region0/dax0.0/uevent:MODALIAS=dax:t0
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/runtime_active_time:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/runtime_active_kids:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/runtime_usage:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/runtime_status:unsupported
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/runtime_suspended_time:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/runtime_enabled:disabled
# /sys/bus/cxl/devices/dax_region0/dax0.0/power/control:auto
# /sys/bus/cxl/devices/dax_region0/dax0.0/target_node:2
# /sys/bus/cxl/devices/dax_region0/dax0.0/numa_node:-1
# /sys/bus/cxl/devices/dax_region0/dax0.0/resource:0x5d0000000
# /sys/bus/cxl/devices/dax_region0/dax0.0/dev:252:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/align:2097152
# /sys/bus/cxl/devices/dax_region0/dax0.0/size:268435456
# /sys/bus/cxl/devices/dax_region0/dax0.0/memmap_on_memory:1
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/page_offset:0x0
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/runtime_active_time:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/runtime_active_kids:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/runtime_usage:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/runtime_status:unsupported
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/runtime_suspended_time:0
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/runtime_enabled:disabled
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/power/control:auto
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/end:0x5dfffffff
# /sys/bus/cxl/devices/dax_region0/dax0.0/mapping0/start:0x5d0000000
# /sys/bus/cxl/devices/dax_region0/dax0.0/modalias:dax:t0
# /sys/bus/cxl/devices/dax_region0/dax_region/id:0
# /sys/bus/cxl/devices/dax_region0/dax_region/align:2097152
# /sys/bus/cxl/devices/dax_region0/dax_region/size:268435456
# /sys/bus/cxl/devices/dax_region0/dax_region/available_size:0
# /sys/bus/cxl/devices/dax_region0/devtype:cxl_dax_region
# /sys/bus/cxl/devices/dax_region0/modalias:cxl:t8
# [root@n4-cxl-fedora-42-containerd fleshutils]# grep -sr . /sys/bus/cxl/devices/dax_region1/
# /sys/bus/cxl/devices/dax_region1/uevent:DEVTYPE=cxl_dax_region
# /sys/bus/cxl/devices/dax_region1/uevent:DRIVER=cxl_dax_region
# /sys/bus/cxl/devices/dax_region1/uevent:MODALIAS=cxl:t8
# /sys/bus/cxl/devices/dax_region1/dax_region/id:1
# /sys/bus/cxl/devices/dax_region1/dax_region/align:2097152
# /sys/bus/cxl/devices/dax_region1/dax_region/size:268435456
# /sys/bus/cxl/devices/dax_region1/dax_region/available_size:0
# /sys/bus/cxl/devices/dax_region1/devtype:cxl_dax_region
# /sys/bus/cxl/devices/dax_region1/dax1.0/uevent:MAJOR=252
# /sys/bus/cxl/devices/dax_region1/dax1.0/uevent:MINOR=1
# /sys/bus/cxl/devices/dax_region1/dax1.0/uevent:DEVNAME=dax1.0
# /sys/bus/cxl/devices/dax_region1/dax1.0/uevent:DRIVER=kmem
# /sys/bus/cxl/devices/dax_region1/dax1.0/uevent:MODALIAS=dax:t0
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/runtime_active_time:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/runtime_active_kids:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/runtime_usage:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/runtime_status:unsupported
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/runtime_suspended_time:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/runtime_enabled:disabled
# /sys/bus/cxl/devices/dax_region1/dax1.0/power/control:auto
# /sys/bus/cxl/devices/dax_region1/dax1.0/target_node:3
# /sys/bus/cxl/devices/dax_region1/dax1.0/numa_node:-1
# /sys/bus/cxl/devices/dax_region1/dax1.0/resource:0x6d0000000
# /sys/bus/cxl/devices/dax_region1/dax1.0/dev:252:1
# /sys/bus/cxl/devices/dax_region1/dax1.0/align:2097152
# /sys/bus/cxl/devices/dax_region1/dax1.0/size:268435456
# /sys/bus/cxl/devices/dax_region1/dax1.0/memmap_on_memory:1
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/page_offset:0x0
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/runtime_active_time:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/runtime_active_kids:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/runtime_usage:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/runtime_status:unsupported
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/runtime_suspended_time:0
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/runtime_enabled:disabled
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/power/control:auto
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/end:0x6dfffffff
# /sys/bus/cxl/devices/dax_region1/dax1.0/mapping0/start:0x6d0000000
# /sys/bus/cxl/devices/dax_region1/dax1.0/modalias:dax:t0
# /sys/bus/cxl/devices/dax_region1/modalias:cxl:t8


echo "launching udev-monitor in the background"
vm-command-q "udev-monitor 2>&1 | tee udev-monitor.output" &

vm-command "set -x
           sleep 2
           sh -c 'grep . /sys/devices/system/node/{online,possible} /sys/devices/system/memory/auto_online_blocks'
           echo online_movable > /sys/devices/system/memory/auto_online_blocks
           sh -c 'grep 0 /sys/devices/system/memory/memory*/online'
           sleep 1
           cxl enable-memdev mem0
           sleep 1
           cxl create-region -t ram -d decoder0.0 -m mem0
           sleep 1
           cxl enable-region region0
           sleep 1
           sh -c 'grep . /sys/devices/system/node/{online,possible}'
           sh -c 'grep 0 /sys/devices/system/memory/memory*/online'
           sh -c 'for f in /sys/devices/system/memory/memory*/online; do echo 1 > \$f; done'
           sleep 1
           sh -c 'grep 0 /sys/devices/system/memory/memory*/online'
           "

echo "hotplugging more memories"
vm-cxl-hotplug cxl_memdev3
vm-cxl-hotplug cxl_memdev1
vm-cxl-hotplug cxl_memdev2
sleep 5
vm-command "cxl list"

echo "hotremoving single memory"
vm-cxl-hotremove cxl_memdev2
sleep 5
vm-command "cxl list"

echo "re-hotplugging hotremoved memory"
vm-cxl-hotplug cxl_memdev2
sleep 5
vm-command "cxl list"

echo "welcome to the end of the show"
breakpoint
