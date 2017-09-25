---
title: "Bugs that Address Sanitizer Doesn't Detect"
header:
  overlay_image: /assets/images/asan/nodetect/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Life is Strange: Before the Storm Stills by Me"
tags:
  - asan
  - vulnresearch
---

A lab for school required us to design 3 examples of memory bugs that are not
detected by Address Sanitizer. I thought it was a pretty informative exercise so
I decided to post it here. Enjoy.

## Bypassing Address Sanitizer

The full C source code is a follows:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct sample {
    char buf[8];
    uint32_t val;
};

void choice1() {
    puts("1. Overflowing a buffer within a struct.");

    struct sample sample_struct;
    printf("sample_struct.val = 0x%x\n", sample_struct.val);
    strncpy(sample_struct.buf, "AAAAAAAABBBB", 12);
    printf("sample_struct.val = 0x%x\n", sample_struct.val);
}

void choice2() {
    puts("2. Arbitrary write with integer overflows skipping over shadow mem.");

    char canary[10] = "IAMCANARY";
    char buf[10];

    printf("Canary = \"%s\"\n", canary);

    int position = 2147483616;
    position = position * 2;
    printf("position = %d\n", position);
    for (int i = 0; i < 9; i++) {
        buf[position + i] = 'X';
        printf("buf[%d] = 'X'\n", position + i);
    }

    printf("Canary = \"%s\"\n", canary);
}

void f1(int ** p) {
    int dangle = 0x41414141;
    *p = &dangle;
}

void f2() {
    int override = 0x42424242;
}

void choice3() {
    puts("3. Use of stack variable after returning from a function.");

    int * p = 0;
    printf("p = %p\n", p);
    printf("*p = undefined\n");

    f1(&p);
    printf("p = %p\n", p);
    printf("*p = 0x%x\n", *p);

    f2();
    printf("p = %p\n", p);
    printf("*p = 0x%x\n", *p);
}

int main(int argc, char ** argv) {

    choice1();
    choice2();
    choice3();

    return 0;
}
```

### Bug 1: Overflowing a Buffer within a Struct

```c
struct sample {
    char buf[8];
    uint32_t val;
};

void choice1() {
    puts("1. Overflowing a buffer within a struct.");

    struct sample sample_struct;
    printf("sample_struct.val = 0x%x\n", sample_struct.val);
    strncpy(sample_struct.buf, "AAAAAAAABBBB", 12);
    printf("sample_struct.val = 0x%x\n", sample_struct.val);
}
```

This example actually features two bugs. The first is use of the uninitialised
field `sample_struct.val` which results in printing of some garbage memory on
the stack. The second bug is that the `strncpy` overflows the
`sample_struct.buf` variable by 4 bytes. This causes `sample_struct.val` to be
overwritten.

```shell
1. Overflowing a buffer within a struct.
sample_struct.val = 0x3ddd09c0
sample_struct.val = 0x42424242
```

### Bug 2: Skipping Over Shadow Memory

```c
void choice2() {
    puts("2. Skipping over shadow memory.");

    char canary[10] = "IAMCANARY";
    char buf[10];

    printf("Canary = \"%s\"\n", canary);

    int position = -64;
    printf("position = %d\n", position);
    for (int i = 0; i < 9; i++) {
        buf[position + i] = 'X';
        printf("buf[%d] = 'X'\n", position + i);
    }

    printf("Canary = \"%s\"\n", canary);
}
```

In this example, it is shown that ASAN can be bypassed if an arbitrary write
primitive is abused to surgically write to a targeted location. An attacker can
simply skip over the shadow bytes that protect a buffer if they know that ASAN
was enabled on a binary to perform the same buffer underrun/overrun with a
little calculation of the offsets.

```shell
2. Skipping over shadow memory.
Canary = "IAMCANARY"
position = -64
buf[-64] = 'X'
buf[-63] = 'X'
buf[-62] = 'X'
buf[-61] = 'X'
buf[-60] = 'X'
buf[-59] = 'X'
buf[-58] = 'X'
buf[-57] = 'X'
buf[-56] = 'X'
Canary = "XXXXXXXXX"
```

### Bug 3: Use of a Stack Variable after Returning from a Function

```c
void f1(int ** p) {
    int dangle = 0x41414141;
    *p = &dangle;
}

void f2() {
    int override = 0x42424242;
}

void choice3() {
    puts("3. Use of stack variable after returning from a function.");

    int * p = 0;
    printf("p = %p\n", p);
    printf("*p = undefined\n");

    f1(&p);
    printf("p = %p\n", p);
    printf("*p = 0x%x\n", *p);

    f2();
    printf("p = %p\n", p);
    printf("*p = 0x%x\n", *p);
}
```

ASAN does not typically detect stack-use-after-return bugs. Thus, any attempts
to use stack pointers from an expired stack frame is not detected by ASAN as a
bug.

```shell
3. Use of stack variable after returning from a function.
p = (nil)
*p = undefined
p = 0x7ffe3ddd08a0
*p = 0x41414141
p = 0x7ffe3ddd08a0
*p = 0x42424242
```
