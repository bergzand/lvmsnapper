LVMSnapper
==========

LVMSnapper is a python tool to create and rotate LVM based snapshots. The need
for this came from the samba shadow copy2 module. Of course this script can be
used for other things that need snapshots. For now LVMSnapper only works with
thin provisioned logical volumes. It should not be hard to adapt it to normal
LVM snapshot, but due to performance reasons I would advise to use thin 
provisioning based snapshots.

LVMSnapper is meant to be run as a cron job. Each run it will check if a
snapshot needs to be made. If so it will snapshot all configured volumes and
mount them under their respective paths. Optionally a symlink can be made
in an other directory to point at the newly mounted snapshot. The newly created
directory has a name formed like @GMT-%Y.%m.%d-%H.%M.%S to comply with the samba
shadow\_copy2 module

LVMSnapper has support for NFS exports and will happily export your new volume
over NFS to any number of hosts. If so, when removing the snapshot it will
unexport the volume again. Although this might be the cleanest way to remove
the snapshot, it might still be necessary to remount the export at the client
side of the NFS mount to detect the change.

Configuration
-------------
### Main
An example configuration file is provided. The main section sets some generic
settings.  
```
[main]
enabled = False
statefile = state
lvm_tag = snapper
lock_file = /run/lvmsnapper.lock
```
* **enabled**: LVMSnapper will not run if this is set to false. This prevents
    it from running when it is not yet fully configured
* **statefile**: A state file is maintained, we need to store it somewhere.
* **lvm_tag**: All snapshots are tagged with a tag. This ensures that we only
    delete snapshots that LVMSnapper made previously
* **lock_file**: Locking ensures that LVMSnapper is started only once. /run
    is probably a good location because it should not persist over reboots.

### Logging
A logging sections is used to configure logging. At the moment this is only
used to configure the log level:
```
[logging]
loglevel = warning
```
Loglevel can be anything of debug, info, warning, error, critical

### Expires
Expire sections define different intervals and expiration times:
```
[expire_1]
#match = h[h] dow dom[dom] m[m]
match = * * * *
expire_after = 1 day
```
They can be named anything as long as it starts with "expire_". The match
defines the intervals and the duration of the snapshot. Match rules have a
cron like syntax, so for example a rule like "`* 1,5,7 2-10 *`" will match
every hour, at monday and friday, between the second and tenth day of the
month of every month. The `expire_after` option defines how long the snapshot
should persist. The longest expire time is determined out of all matching
expire sections. So if you define multiple expires, that match at a certain
moment, the longest time among those is taken as an expiration.

### Snapshots
All other sections are considered to be snapshot definitions. For example: 
```
[home]
mountoptions = discard,ro
mount = /home
vg = vg
lv = tlv-home
snapdir = /snapshots/home
linkdir = /home/.snapshots
nfsexports = 10.1.1.0/24
nfsoptions = ro,async,wdelay,nohide,no_subtree_check
```
This is a complete example of a snapshot definition.
* **mountoptions**: The options given to `mount` for mounting the snapshots.
* **mount**: the mount point of the original volume.
* **vg**: The volume group containing the logical volumes.
* **lv**: The original logical volume to be snapshotted.
* **snapdir**: The directory to create mount points in for the snapshots.
* **linkdir**: If specified, symlinks will be created in this directory 
    pointing to the mount directories.
* **nfsexports**: If specified, the new mount will be exported to these
    ip's. Multiple subnets, ip's or hostnames can be specified, space 
    separated.
* **nfsoptions**: Options to be fed to exportfs for the nfs exports. This
    option is ignored if no nfsexports are defined.


Risk
----
Please notice that when using this script you give a program the responsibilty
to automatically create and delete logical volumes. Please undestand that
things might go wrong. I've tried to build in as many sanity checks as
possible, but since all software contains bugs, there is always a risk that
it accidentally deletes the wrong volume.
Also, this software is not meant as a complete backup solution. You might be
able to use it with your backup solution, but if your disks fail, your
snapshots are also gone.

TODO
----
* Command line parameters
* Support for regular LVM snapshots
