---
title: "Sieberrsec 3.0 CTF (2021) - totallyfoolproofcrypto (Crypto)"
header:
  overlay_image: /assets/images/sieberrsec3.0/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sieberrsec 3.0 CTF Organisers"

tags:
  - sieberrsec
  - sieberrsec3.0
  - writeup
  - crypto
  - byte by byte
  - aes
  - ecb
---

Summary: A dump of a Windows user's AppData containing Google Chrome library data files and Windows
DPAPI master key files can be used in conjunction with the user's computer password to extract saved
website login credentials.

## Challenge Prompt

```
totallyfoolproofcrypto
Cryptography

Solves (7) - 884 Points

In hindsight, rolling my own crypto was a rather stupendous stroke of stupidity. I'll be switching to a well-known, verified library to fix this.

from Crypto.Util.Padding import pad,unpad
from Crypto.Cipher import AES
import os

with open("flag", 'rb') as f: flag = f.read().strip()
key = os.urandom(16)

while 1:
    pt = input('> ').encode()
    padded = pad(pt+flag, AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    print(cipher.encrypt(padded).hex())
nc challs.sieberrsec.tech 31311

A first blood prize of one (1) month of Discord Nitro is available for this challenge.

Some amount of "bruteforce" will be necessary -- and hence legal -- for this challenge.
```

## Solution

This challenge is a pretty standard byte-by-byte ECB oracle challenge. For an illustrated writeup,
please see this [excellent article](https://c0nradsc0rner.com/2016/07/03/ecb-byte-at-a-time/) by
c0nrad.

First, let's identify the maximum possible number of blocks comprising the flag. We can do this by
sending an empty prefix and getting a sample encrypted output.

```console
nc challs.sieberrsec.tech 31311
>
d4037cd10db2222f01cf737f8f08353c7879f5d8932dfea5916d8ea68e943681b5eed8d24350b43ae5c1be9f26e58b90
>
```

Some quick math tells us that the likely number of blocks is 3.

```console
In [243]: len('d4037cd10db2222f01cf737f8f08353c7879f5d8932dfea5916d8ea68e943681b5eed8d24350b43ae5c1be9f26e58b90')/2/16
Out[243]: 3.0
```

We can start off with an initial trial of `A` characters of length `3 * 16` and iterating through
possible candidates (restricted to just a subset of printable bytes) to obtain the flag byte-by-byte
with the following script:

```python
#!/usr/bin/env python

import string
from pwn import *

# context.log_level = 'debug'

max_blocks = 3
block_size = 16

def main():
    p = remote('challs.sieberrsec.tech', 31311)

    max_size_secret = max_blocks * block_size
    secret = b''

    for size in range((max_size_secret - 1), -1, -1):
        # Original
        origin = b"A" * size
        p.recvuntil(b'> ')
        p.sendline(origin)
        original_blocks = p.recvline().strip()

        tmp = b"A" * size + secret
        for character in string.printable[:95]:
            cur_line = tmp + character.encode()
            p.recvuntil(b'> ')
            p.sendline(cur_line)
            candidate_blocks = p.recvline().strip()
            if original_blocks[:max_size_secret * 2] == candidate_blocks[:max_size_secret * 2]:
                secret += character.encode()
                log.info('{}'.format(secret.decode()))
                break

        if len(secret) + size <= max_size_secret - 1:
            log.success('Flag: {}'.format(secret.decode()))
            return


if __name__ == '__main__':
    main()
```

Running the script gives us the flag:

```console
$ python solve.py
[+] Opening connection to challs.sieberrsec.tech on port 31311: Done
[*] I
[*] IR
[*] IRS
[*] IRS{
[*] IRS{w
[*] IRS{w0
[*] IRS{w0w
[*] IRS{w0w_
[*] IRS{w0w_w
[*] IRS{w0w_wh
[*] IRS{w0w_wh@
[*] IRS{w0w_wh@t
[*] IRS{w0w_wh@t_
[*] IRS{w0w_wh@t_a
[*] IRS{w0w_wh@t_an
[*] IRS{w0w_wh@t_an_
[*] IRS{w0w_wh@t_an_0
[*] IRS{w0w_wh@t_an_0r
[*] IRS{w0w_wh@t_an_0ri
[*] IRS{w0w_wh@t_an_0rig
[*] IRS{w0w_wh@t_an_0rig1
[*] IRS{w0w_wh@t_an_0rig1n
[*] IRS{w0w_wh@t_an_0rig1na
[*] IRS{w0w_wh@t_an_0rig1nal
[*] IRS{w0w_wh@t_an_0rig1nal_
[*] IRS{w0w_wh@t_an_0rig1nal_p
[*] IRS{w0w_wh@t_an_0rig1nal_pr
[*] IRS{w0w_wh@t_an_0rig1nal_pr0
[*] IRS{w0w_wh@t_an_0rig1nal_pr0b
[*] IRS{w0w_wh@t_an_0rig1nal_pr0bl
[*] IRS{w0w_wh@t_an_0rig1nal_pr0bl3
[*] IRS{w0w_wh@t_an_0rig1nal_pr0bl3m
[*] IRS{w0w_wh@t_an_0rig1nal_pr0bl3m}
[+] Flag: IRS{w0w_wh@t_an_0rig1nal_pr0bl3m}
```

**Flag:** `IRS{w0w_wh@t_an_0rig1nal_pr0bl3m}`
