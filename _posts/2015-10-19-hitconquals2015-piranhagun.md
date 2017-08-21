---
title: "HITCON 2015 Qualifiers - Piranha Gun (Stego)"
header:
  overlay_image: /assets/images/hitconquals2015/piranhagun/header.jpg
  overlay_filter: 0.5
tags:
  - hitconquals2015
  - writeup
  - steganography
---

Directory contents are hidden with a mount.

## Challenge Description

#### Description

```
The Piranha Gun is a post-Plantera Hardmode ranged weapon that fires a single,
returning “piranha” projectile that costs no ammunition.

nc 54.178.235.243 10004
```

## Solution

In this challenge, we get a server to netcat into. Netcatting into the server
drops us into a shell.

```shell
$ nc 54.178.235.243 10004
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
root@ip-172-31-19-201:/home/PiranhaGun#
```

There was a README in the home directory.

```shell
root@ip-172-31-19-201:/home/PiranhaGun# ls
ls
README
root@ip-172-31-19-201:/home/PiranhaGun# cat README
cat README
The Piranha Gun can be found in "jungle.chest".
```

Let's take a look at the processes.

```shell
root@ip-172-31-19-201:/home/PiranhaGun# ps aux
ps aux
Error, do this: mount -t proc proc /proc
root@ip-172-31-19-201:/home/PiranhaGun# mount -t proc proc /proc
mount -t proc proc /proc
root@ip-172-31-19-201:/home/PiranhaGun# ps aux
ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   2116    56 ?        S    19:30   0:00 wrapper root 0 600 262144 /home/PiranhaGun /bin/bash -i
root         2  0.0  0.0  18196  3276 ?        S    19:30   0:00 /bin/bash -i
root         9  0.0  0.0  15572  2104 ?        R    19:31   0:00 ps aux
```

Nothing that interesting. But let's take a look at what's in /proc.

```shell
root@ip-172-31-19-201:/home/PiranhaGun# ls -la /proc
ls -la /proc
total 4
dr-xr-xr-x 114 nobody nogroup               0 Oct 18 19:30 .
drwxr-xr-x  23 nobody nogroup            4096 Oct 16 13:29 ..
dr-xr-xr-x   9 root   root                  0 Oct 18 19:31 1
dr-xr-xr-x   9 root   root                  0 Oct 18 19:32 10
dr-xr-xr-x   9 root   root                  0 Oct 18 19:31 2
dr-xr-xr-x   2 nobody nogroup               0 Oct 18 19:32 acpi
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 buddyinfo
dr-xr-xr-x   4 nobody nogroup               0 Oct 18 19:32 bus
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 cgroups
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 cmdline
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 consoles
...
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 meminfo
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 misc
-r--r--r--   1 nobody nogroup               0 Oct 18 19:32 modules
lrwxrwxrwx   1 nobody nogroup              11 Oct 18 19:32 mounts -> self/mounts
-rw-r--r--   1 nobody nogroup               0 Oct 18 19:32 mtrr
...
```

There's a lot of things to look through, and we took awhile but eventually we
came across the `/proc/mounts` file.

```shell
cat /proc/mounts
/dev/disk/by-uuid/2ed4c374-2ddb-4a75-af24-98df753dbf6d / ext4 rw,relatime,discard,data=ordered 0 0
udev /dev devtmpfs rw,relatime,size=15702768k,nr_inodes=3925692,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=3141528k,mode=755 0 0
none /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
none /run/shm tmpfs rw,nosuid,nodev,relatime 0 0
none /run/user tmpfs rw,nosuid,nodev,noexec,relatime,size=102400k,mode=755 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
none /sys/fs/cgroup tmpfs rw,relatime,size=4k,mode=755 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,relatime,cpuset 0 0
cgroup /sys/fs/cgroup/cpu cgroup rw,relatime,cpu 0 0
cgroup /sys/fs/cgroup/cpuacct cgroup rw,relatime,cpuacct 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,relatime,memory 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,relatime,devices 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,relatime,freezer 0 0
cgroup /sys/fs/cgroup/net_cls cgroup rw,relatime,net_cls 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,relatime,blkio 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/net_prio cgroup rw,relatime,net_prio 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,relatime,hugetlb 0 0
systemd /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,name=systemd 0 0
none /sys/fs/fuse/connections fusectl rw,relatime 0 0
none /sys/kernel/debug debugfs rw,relatime 0 0
none /sys/kernel/security securityfs rw,relatime 0 0
none /sys/fs/pstore pstore rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/disk/by-uuid/2ed4c374-2ddb-4a75-af24-98df753dbf6d /chest ext4 rw,relatime,discard,data=ordered 0 0
proc /proc proc rw,nodev,relatime 0 0
```

And we notice that `/chest` has something mounted at that location. Looking in
`/chest` yields nothing.

```shell
root@ip-172-31-19-201:/home/PiranhaGun# ls /chest
ls /chest
root@ip-172-31-19-201:/home/PiranhaGun#
```

It wasn't apparent, but unmounting that location uncovered something. I guess
that when it was mounted, it hid whatever was there before.

```shell
root@ip-172-31-19-201:/home/PiranhaGun# umount /chest
umount /chest
root@ip-172-31-19-201:/home/PiranhaGun# ls -la /chest
ls -la /chest
total 12
drwxr-xr-x  2 nobody nogroup 4096 Oct 16 13:31 .
drwxr-xr-x 23 nobody nogroup 4096 Oct 16 13:29 ..
-rw-r--r--  1 nobody nogroup   42 Oct 16 13:08 jungle.chest
```

Reading the flag:

```shell
root@ip-172-31-19-201:/home/PiranhaGun# cat /chest/jungle.chest
cat /chest/jungle.chest
hitcon{Wh1re d!d Y0u F1nd the Jungle Key}
```

It's a little like opening a chest.

Flag: **hitcon{Wh1re d!d Y0u F1nd the Jungle Key}**
