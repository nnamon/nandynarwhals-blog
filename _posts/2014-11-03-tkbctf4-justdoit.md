---
title: "TKBCTF 4 - Just Do It"
tags:
  - tkbctf4
  - writeup
  - reversing
---

We were given a x86-64 Windows PE binary to reverse.

My solution script:

```python
import struct
import string

if __name__ == "__main__":
    parts = []
    parts.append(0x00f0c3eac5dfc8c2)
    parts.append(0x00fec8e3e0fef0e5)
    parts.append(0x00f6d0f4f5f6e5c0)
    parts.append(0x00e9abeee6edfbf6)

    flag = ""
    for i in range(4):
        bytes = struct.pack("Q", parts[i])[:-1]
        plain = "".join(map(chr, [ord(j)^(0x91+i) for j in bytes]))
        flag += plain

    print "ROT13 Flag: %s" % flag

    rot13 = string.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")

    print "Plain Flag: %s" % string.translate(flag, rot13)
```

Flag: **FLAG{EnjoyedMyFirstProblem?}**
