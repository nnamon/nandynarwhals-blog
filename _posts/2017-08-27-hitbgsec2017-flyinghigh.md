---
title: "HITBGSEC CTF 2017 - flying\_high (Misc)"
header:
  overlay_image: /assets/images/hitbgsec2017/flyinghigh/header.jpg
  overlay_filter: 0.5
  caption: "Photo credits: Sawyer Bengtson on Unsplash"
tags:
  - hitbgsec2017
  - writeup
  - forensics
---

UBIFS images are recovered from a crashed drone and the flag is included in the
video of the drone's last moments.

## Challenge Description

#### Points

281

#### Description

```
We found a crashed drone, are you able to recover information what this drone was doing?
Flying_High.tar.gz:43ce56686b4f38b68108140825434f76bfed47530a92f3a6469c202746c257f2
```

#### Files

- [158195de-cd06-4837-98e5-1129101fb2e4.gz]({{ site.url }}{{ site.baseurl }}/assets/files/hitbgsec2017/flyinghigh/158195de-cd06-4837-98e5-1129101fb2e4.gz)

## Solution

First, we extract the files and see that there are a four binary files.

```shell
$ tar xvfz 158195de-cd06-4837-98e5-1129101fb2e4.gz
image0.bin
image1.bin
image2.bin
image3.bin
```

If we run file on all of the images, we can see that they are UBIFS images.

```shell
$ file *.bin
image0.bin: UBIfs image, sequence number 1, length 4096, CRC 0x03a905a7
image1.bin: UBIfs image, sequence number 1, length 4096, CRC 0x47b22f13
image2.bin: UBIfs image, sequence number 1, length 4096, CRC 0xf7f7a9b7
image3.bin: UBIfs image, sequence number 1, length 4096, CRC 0x68fa15bd
```

At first we tried to mount them but it did not work very well because it was a
pain trying to install `nand_sim`. So, I discovered the
[ubi\_reader](https://github.com/jrspruitt/ubi_reader) utility and used it to
extract all the images to disk.

```shell
$ for i in `ls *.bin`; do ubireader_extract_files $i -o extracted_$i; done
Extracting files to: extracted_image0.bin
Extracting files to: extracted_image1.bin
extract_dents Warn: DEV Fail: unpack requires a string argument of length 8
extract_dents Warn: DEV Fail: unpack requires a string argument of length 8
extract_dents Warn: DEV Fail: unpack requires a string argument of length 8
extract_dents Warn: DEV Fail: unpack requires a string argument of length 8
Extracting files to: extracted_image2.bin
read Error: Block ends at 4299020519 which is greater than file size 16887808
index Fatal: LEB: 31, UBIFS offset: 4053224, error: Bad Read Offset Request
Extracting files to: extracted_image3.bin
```

There wasn't much in the first image.

```shell
 ls -la extracted_image0.bin/
total 44
drwxr-xr-x 1 ubuntu ubuntu  340 Aug 26 20:30 .
drwxr-xr-x 1 ubuntu ubuntu  374 Aug 26 20:30 ..
-rw-r--r-- 1 ubuntu ubuntu 9803 Aug 26 20:30 FVT1_scripts.zip
-rw-r--r-- 1 ubuntu ubuntu 6843 Aug 26 20:30 FVT1_trace.txt
-rw-r--r-- 1 ubuntu ubuntu   18 Aug 26 20:30 mac_address.txt
-rw-r--r-- 1 ubuntu ubuntu  114 Aug 26 20:30 parameters.xml
-rw-r--r-- 1 ubuntu ubuntu  786 Aug 26 20:30 production_info.xml
-rw-r--r-- 1 ubuntu ubuntu   19 Aug 26 20:30 serial.txt
-rw-r--r-- 1 ubuntu ubuntu   45 Aug 26 20:30 uid.txt
-rw-r--r-- 1 ubuntu ubuntu   18 Aug 26 20:30 vertical_camera_calibration.txt
```

The second just seemed to contain system files.

```shell
$ ls -la extracted_image1.bin/
total 0
drwxr-xr-x 1 ubuntu ubuntu  680 Aug 26 20:30 .
drwxr-xr-x 1 ubuntu ubuntu  374 Aug 26 20:30 ..
drwxr-xr-x 1 ubuntu ubuntu 2856 Aug 26 20:30 bin
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 data
drwxr-xr-x 1 ubuntu ubuntu  102 Aug 26 20:30 dev
drwxr-xr-x 1 ubuntu ubuntu  612 Aug 26 20:30 etc
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 factory
drwxr-xr-x 1 ubuntu ubuntu  238 Aug 26 20:30 firmware
drwxr-xr-x 1 ubuntu ubuntu  102 Aug 26 20:30 home
drwxr-xr-x 1 ubuntu ubuntu 1292 Aug 26 20:30 lib
drwxr-xr-x 1 ubuntu ubuntu  102 Aug 26 20:30 licenses
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 mnt
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 proc
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 root
drwxr-xr-x 1 ubuntu ubuntu 1394 Aug 26 20:30 sbin
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 sys
drwxr-xr-x 1 ubuntu ubuntu  136 Aug 26 20:30 tmp
drwxr-xr-x 1 ubuntu ubuntu   68 Aug 26 20:30 update
drwxr-xr-x 1 ubuntu ubuntu  272 Aug 26 20:30 usr
drwxr-xr-x 1 ubuntu ubuntu  170 Aug 26 20:30 var
```

The third contained nothing.

```shell
$ ls -la extracted_image2.bin/
total 0
drwxr-xr-x 1 ubuntu ubuntu  68 Aug 26 20:30 .
drwxr-xr-x 1 ubuntu ubuntu 374 Aug 26 20:30 ..
```

However, the fourth contained the interesting blackbox information.

```shell
$ ls -la extracted_image3.bin/
total 172
drwxr-xr-x 1 ubuntu ubuntu    510 Aug 26 20:30 .
drwxr-xr-x 1 ubuntu ubuntu    374 Aug 26 20:30 ..
-rw-r--r-- 1 ubuntu ubuntu     12 Aug 26 20:30 accs_infos.bin
-rw-r--r-- 1 ubuntu ubuntu   5087 Aug 26 20:30 config.ini
-rw-r--r-- 1 ubuntu ubuntu   5080 Aug 26 20:30 config.ini.old
drwxr-xr-x 1 ubuntu ubuntu    170 Aug 26 20:30 custom.configs
-rw-r--r-- 1 ubuntu ubuntu   5148 Aug 26 20:30 emergency.bin
-rw-r--r-- 1 ubuntu ubuntu 124642 Aug 26 20:30 ephemeris.ee
-rw-r--r-- 1 ubuntu ubuntu     12 Aug 26 20:30 fact_accs_infos.bin
-rw-r--r-- 1 ubuntu ubuntu     20 Aug 26 20:30 fact_trims.bin
-rw-r--r-- 1 ubuntu ubuntu      0 Aug 26 20:30 gps.log
-rw-r--r-- 1 ubuntu ubuntu      2 Aug 26 20:30 old_adress.txt
-rw-r--r-- 1 ubuntu ubuntu     19 Aug 26 20:30 random_mac.txt
-rw-r--r-- 1 ubuntu ubuntu     20 Aug 26 20:30 trims.bin
drwxr-xr-x 1 ubuntu ubuntu    238 Aug 26 20:30 video
```

After exploring the data, we find a video containing a few seconds of the
drone's last moments.

```shell
$ ls -la extracted_image3.bin/video/usb/
total 3152
drwxr-xr-x 1 ubuntu ubuntu     102 Aug 26 20:30 .
drwxr-xr-x 1 ubuntu ubuntu     238 Aug 26 20:30 ..
-rw-r--r-- 1 ubuntu ubuntu 3224237 Aug 26 20:30 video_20170817_150007.mov
```

Watching the video gives us the flag.

<iframe width="1920" height="795" src="https://www.youtube.com/embed/aHHfN1yA7E4" frameborder="0" allowfullscreen></iframe>`

Flag: **HITB{96ac9a0458279711e5d61f10849e6c58}**
