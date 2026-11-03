```{include} ../../../deployment/helm/dra-driver-cxl/README.md
```

## Usage

How to claim CXL memory with the driver is described in
[CXL memory usage](../../memory/cxl/usage.md).

The DeviceClass `cxl-local-persistent` of the chart selects the local
memdevs of persistent memory, whose claims get the block device or a
filesystem of the memdev
([persistent local memdevs](../../memory/cxl/local.md#persistent-local-memdevs));
`cxl-local` and `cxl-local-shared` select local memdevs that are not
persistent. Two keys of `config` are about filesystems of persistent
memory:

- `fsTypes`: the filesystem types that mode `fs` mounts on the node
  (default `[erofs, squashfs, ext4, xfs, btrfs, gfs2]`); `[erofs]` keeps
  the kernel of the node from parsing other filesystems that tenants
  write.
- `memdevSettings[].coherent`: the memory of a local memdev in
  `sharedDevices` is coherent between the hosts that share it, so that a
  cluster filesystem may be read-write on it.

See the
[configuration file](../../memory/cxl/usage.md#configuration-file).

Upgrades: `cxl-local` and `cxl-local-shared` test the attribute
`persistent`, which the ResourceSlices of an older driver lack, so claims
of these classes do not allocate until the new driver has published its
ResourceSlices again. Upgrade the DaemonSet before the classes, or expect
that window ([DeviceClasses](../../memory/cxl/usage.md#deviceclasses)).
