---
title: "HITBGSEC CTF 2017 - 1000levels (Pwn)"
header:
  overlay_image: /assets/images/hitbgsec2017/1000levels/header.jpg
  overlay_filter: 0.5
  caption: "Photo credits: Rebecca Li on Unsplash"
tags:
  - hitbgsec2017
  - writeup
  - pwn
---

Uninitialised variable usage allows for reliable exploitation of a classic stack
overflow on a NX and PIE enabled binary.

## Challenge Description


#### Points

200

#### Author

amon

#### Description

```
It's more diffcult.

nc 47.74.147.103 20001
```

#### Files

- [498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz](https://hitb.xctf.org.cn/media/task/498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz)

## Solution

![1]({{ site.url }}{{ site.baseurl }}/assets/images/32c3/teufel/1.png){: .align-center}

[![asciicast](https://asciinema.org/a/hkB2nBw48CADpbHaeuvkZF9zO.png)](https://asciinema.org/a/hkB2nBw48CADpbHaeuvkZF9zO)

Flag: **HITB{d989d44665a5a58565e09e7442606506}**
