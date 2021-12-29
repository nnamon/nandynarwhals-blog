---
title: "Sieberrsec 3.0 CTF (2021) - Can You Math It? (Misc)"
header:
  overlay_image: /assets/images/sieberrsec3.0/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sieberrsec 3.0 CTF Organisers"

tags:
  - sieberrsec
  - writeup
  - misc
  - eval
---

Summary: Typical math scripting challenge. Just providing the solution for a safeeval version to
avoid insecure evaluation of untrusted inputs.

## Challenge Prompt

```
Can You Math It?
Miscellaneous

Solves (25) - 313 Points

Can you solve 100 math equations?

What if you only have 5 seconds to solve each?

Server source code available here

[This is a scripting challenge. You are expected to write a script to solve it.]

Connect to the challenge at nc challs.sieberrsec.tech 29079
```

## Solution

The source code is given but is really not required. Just useful to verify that the math challenges
provided aren't too crazy.

```python
from time import time, sleep
from random import randint, choice

operations = ('+', '-', '*', '/')

def givechal():
    # generate and solve equation, return both question and answer
    challenge = str(randint(1, 999)) + ' ' + choice(operations) + ' ' + str(randint(1, 999)) + ' ' + choice(operations) + ' ' + str(randint(1, 999))
    result = int(eval(challenge))
    return challenge, result

def main():
    # intro
    print('Can You Math It?')
    sleep(1) # add some arbitrary delay
    print('You have 5 seconds to answer each question')
    print('You have 100 questions to solve')
    print('Please give all answers to nearest integer')
    print('Good luck')
    sleep(1)
    for i in range(100):
        challenge, result = givechal() # generate and store question and answer
        print('Solve ', challenge, ' :') # show the question
        start = time() # start a timer
        answer = input() # receive answer
        timetaken = time() - start # stop timer, calculate time taken
        if timetaken < 5 and answer == str(result): # if within time limit and correct answer
            print('Correct!')
            print('Next question')
        elif timetaken > 5: # if more than 5 secs taken
            print('Took longer than 5 seconds')
            exit()
        else: # answer wrong
            print('Wrong answer')
            exit()
    print('Congratulations! You CAN math it')
    print('The flag is IRS{FLAG_REDACTED}') # the flag goes here

if __name__ == '__main__':
    main() # run the program
```

Pwntools offers the `safeeval` utility to safely evaluate expressions. We can use this to solve the
script without fear of shenanigans.

```python
#!/usr/bin/env python

from pwn import *

# context.log_level = 'debug'

def main():
    p = remote('challs.sieberrsec.tech', 29079)

    for i in range(100):
        p.recvuntil(b'Solve  ')
        challenge = p.recvuntil(b':')[:-1].strip()
        solution = int(util.safeeval.expr(challenge))
        p.sendline(str(solution).encode())
        log.info('Challenge {}: {} = {}'.format(i, challenge.decode(), solution))

    p.recvuntil(b'Congratulations! You CAN math it\n')
    log.success(p.recvline())

if __name__ == '__main__':
    main()

```

Running the script yields the flag:

```console
$ python exploit.py
[+] Opening connection to challs.sieberrsec.tech on port 29079: Done
[*] Challenge 0: 360 / 510 / 350 = 0
[*] Challenge 1: 845 - 303 / 294 = 843
[*] Challenge 2: 814 * 232 - 427 = 188421
[*] Challenge 3: 924 / 510 - 714 = -712
[*] Challenge 4: 941 + 367 - 712 = 596
[*] Challenge 5: 772 / 294 + 734 = 736
[*] Challenge 6: 86 * 323 / 191 = 145
[*] Challenge 7: 189 / 532 + 830 = 830
[*] Challenge 8: 473 / 788 - 500 = -499
[*] Challenge 9: 639 * 889 * 190 = 107933490
[*] Challenge 10: 611 / 508 / 240 = 0
...
[*] Challenge 94: 698 * 558 - 118 = 389366
[*] Challenge 95: 922 - 815 + 252 = 359
[*] Challenge 96: 82 * 147 - 947 = 11107
[*] Challenge 97: 719 / 91 * 360 = 2844
[*] Challenge 98: 444 - 463 - 478 = -497
[*] Challenge 99: 104 - 284 / 650 = 103
[+] The flag is IRS{4f2cd85d0a9f32f4}
```

**Flag:** `IRS{4f2cd85d0a9f32f4}`
