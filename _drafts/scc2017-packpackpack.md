---
title: "Singapore Cyber Conquest 2017 - Pack! Pack! Pack! (Misc)"
header:
  overlay_image: /assets/images/scc2017/packpackpack/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Forrest Cavale on Unsplash"
tags:
  - scc2017
  - writeup
  - miscellaneous
---

Simple

## Challenge Description

#### Points

100

#### Description

```
You are given a link
```

#### Solvers

15 Teams solved

## Solution

The binary is a simple crackme challenge that prompts for the flag input.

```shell
$ ./6ca404a82514da5ef82fd6213e4f5e63_rev1
Give me your magic:ABCDEF
Try your best :)
```

If we decompile the `main` function, we can see that the user input is passed
through a few checks.

{% raw %}
```c
int main() {
    memset(&var_30, 0x0, 0x28);
    setvbuf(*stdout@@GLIBC_2.2.5, 0x0, 0x2, 0x0);
    setvbuf(*stdin@@GLIBC_2.2.5, 0x0, 0x2, 0x0);
    printf("Give me your magic:");
    read(0x0, &var_30, 0x20);
    if (((check1(&var_30) != 0x0) && (check2(&var_30 + 0x8) != 0x0)) &&
         (check3(&var_30 + 0x10) != 0x0)) {
            if (check4(&var_30 + 0x18) != 0x0) {
                    rax = printf("Here is your flag : FLAG{%s}\n", &var_30);
            }
            else {
                    rax = puts("Try your best :)");
            }
    }
    else {
            rax = puts("Try your best :)");
    }
    return rax;
}
```

Since the program looks like it's really simple. We can try writing an angr
script to solve it.
```python
import angr

p = angr.Project("./6ca404a82514da5ef82fd6213e4f5e63_rev1")

@p.hook(0x40088d)
def printf_flag(state):
    print "FLAG{%s}" % state.posix.dump_fd(0)
    p.terminate_execution()

p.execute()
```

The address `0x40088d` corresponds to the following disassembly.

```shell
0040088d  mov     edi, 0x40099b  {"Here is your flag : FLAG{%s}\n"}
```
{% endraw %}

Running the script yields our flag instantly.

```shell
$ sudo docker run -v /vagrant/scc/rev1/:/rev1 -it angr/angr
(angr) angr@95b147957010:~$ cd /rev1/
(angr) angr@95b147957010:/rev1$ ls
6ca404a82514da5ef82fd6213e4f5e63_rev1
peda-session-6ca404a82514da5ef82fd6213e4f5e63_rev1.txt  solve  solver.py
(angr) angr@95b147957010:/rev1$ python solver.py
FLAG{s3cur1ty_w0uld_r3v3rs3_y0ur_l1f3}
(angr) angr@95b147957010:/rev1$
```

Flag: **FLAG{s3cur1ty\_w0uld\_r3v3rs3\_y0ur\_l1f3}**
