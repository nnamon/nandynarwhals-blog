---
title: "STACK 2020 - Walking Down Memory Lane (Forensics)"
header:
  overlay_image: /assets/images/stack-2020/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Steve Johnson"

tags:
  - stack
  - writeup
  - forensics
  - steganography
  - memory dump
---

Summary: Analysing the provided memory dump yields a hosted PNG file containing a steganographic message.

![Challenge Description]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/CEFFBF7464C74964A635BA298E31628F.jpg){: .align-center}

```
Walking down a colourful memory lane
991 FORENSICS
16 SOLVES

DESCRIPTION
We are trying to find out how did our machine get infected. What did the user do?

This challenge:
- Is eligible for Awesome Write-ups Award
- Prerequisite for Mastery Award - Forensicator
```

For this challenge, we are given a memory dump file.

```console
$ ls -la
-rwxrwxrwx  1 amon  staff  2147483648 Dec  3 19:33 forensics-challenge-1.mem
```

To analyse this, we can use a dockerised version of Volatility.

```console
$ docker pull blacktop/volatility
```

To start, we need to identify the operating system profile of the image. This can be done with the `imageinfo` plugin.

```console
$ docker run --rm -v `pwd`:/data:ro blacktop/volatility -f forensics-challenge-1.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/data/forensics-challenge-1.mem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800029fb0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800029fcd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-12-03 09:12:22 UTC+0000
     Image local date and time : 2020-12-03 17:12:22 +0800
```

Now, we can use the `Win7SP1x64` profile to perform further analysis. Next, dumping the process tree with `pstree` tells us that two interesting processes were running: `chrome.exe` and `notepad.exe`.

```
console
$ docker run --rm -v `pwd`:/data:ro blacktop/volatility -f forensics-challenge-1.mem --profile Win7SP1x64 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa801a3dd7f0:explorer.exe                     2460   2432     32    905 2020-12-03 08:51:58 UTC+0000
. 0xfffffa801aed8060:notepad.exe                     3896   2460      5    286 2020-12-03 09:10:52 UTC+0000
. 0xfffffa801ac4d060:RamCapture64.e                  4832   2460      6     70 2020-12-03 09:11:24 UTC+0000
. 0xfffffa80199e6a70:chrome.exe                      2904   2460     33   1694 2020-12-03 09:10:20 UTC+0000
.. 0xfffffa801ad9eb30:chrome.exe                     3328   2904     13    231 2020-12-03 09:10:33 UTC+0000
.. 0xfffffa801ae2e7d0:chrome.exe                     3456   2904     12    196 2020-12-03 09:10:42 UTC+0000
.. 0xfffffa801addfb30:chrome.exe                     3380   2904     13    304 2020-12-03 09:10:34 UTC+0000
.. 0xfffffa801ae269e0:chrome.exe                     3444   2904     13    231 2020-12-03 09:10:38 UTC+0000
...
. 0xfffffa801a17db30:lsm.exe                          504    376     10    146 2020-12-03 08:51:25 UTC+0000
 0xfffffa8018dac040:System                              4      0     86    572 2020-12-03 08:51:24 UTC+0000
. 0xfffffa8019355b30:smss.exe                         240      4      2     29 2020-12-03 08:51:24 UTC+0000
```

Since Chrome is involved, we can use the Chrome History volatility plugin written by [Dave Lassalle](https://blog.superponible.com/2014/08/31/volatility-plugin-chrome-history/).

Running the plugin gives us a list of URLs visited by the user.

```console
$  docker run --rm -v `pwd`:/data blacktop/volatility --plugins=volatility-plugins/ -f forensics-challenge-1.mem --profile Win7SP1x64 chromehistory
...
```

![Output from the Chrome History Plugin]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/82E358D9353301208F1760D64A2D06C7.jpg){: .align-center}

The URL [http://www.mediafire.com/view/5wo9db2pa7gdcoc/] looked extremely suspicious. Downloading the file hosted at the link gives us an extremely tiny PNG:

![Tiny PNG]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/0E112A3176BA7CA1F975F10E4EAEA28F.jpg){: .align-center}

Examining the file shows that it is a valid PNG but contains very little data:

```console
$ file This\ is\ a\ png\ file.png
This is a png file.png: PNG image data, 64 x 1, 8-bit/color RGB, non-interlaced
$ xxd This\ is\ a\ png\ file.png
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0040 0000 0001 0802 0000 00e1 0f3f  ...@...........?
00000020: 4000 0000 3249 4441 5478 9c63 4ccf 2fe3  @...2IDATx.cL./.
00000030: fdf6 f6cb 0906 6e2b 895f 673e 1db6 e7d1  ......n+._g>....
00000040: 7fb0 8bf5 abfd f937 7ff8 2dd9 3ff2 719c  .......7..-.?.q.
00000050: 6d6b 6618 c400 004e 9312 0298 1553 a700  mkf....N.....S..
00000060: 0000 0049 454e 44ae 4260 82              ...IEND.B`.
```

Suspecting that the file hides some data through steganography techniques, we can use `zsteg` to automatically attempt extracting data through a variety of schemes and reveal a possible flag.

```console
$ zsteg -a This\ is\ a\ png\ file.png
b8,r,lsb,xy         .. text: "gthsm0_d3B3"
b8,g,lsb,xy         .. text: "oe-g3rRG3lz"
b8,b,lsb,xy         .. text: "vcc{my3rnu}"
b8,rgb,lsb,xy       .. text: "govtech-csg{m3m0ry_R3dGr33nBlu3z}"
b8,bgr,lsb,xy       .. text: "vogcetc-h{gsm3myr03R_rGdn33ulB}z3"
b8,rgb,lsb,xy,prime .. text: "h-csg{0rydGr"
b8,bgr,lsb,xy,prime .. text: "c-h{gsyr0rGd"
b8,r,lsb,XY         .. text: "3B3d_0mshtg"
b8,g,lsb,XY         .. text: "zl3GRr3g-eo"
b8,b,lsb,XY         .. text: "}unr3ym{ccv"
b8,rgb,lsb,XY       .. text: "3z}Blu33ndGr_R30rym3msg{h-ctecgov"
b8,bgr,lsb,XY       .. text: "}z3ulBn33rGd3R_yr0m3m{gsc-hcetvog"
b8,rgb,lsb,XY,prime .. text: "3z}m3mh-c"
b8,bgr,lsb,XY,prime .. text: "}z3m3mc-h"
```

**Flag:** `govtech-csg{m3m0ry_R3dGr33nBlu3z}`
