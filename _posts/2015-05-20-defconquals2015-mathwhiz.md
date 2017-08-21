---
title: "DEFCON CTF Qualifiers 2015 - MathWhiz (Baby's First)"
tags:
  - defconquals2015
  - writeup
  - programming
---

Simple programming challenge in which you had to solve equations in different
formats.

## Challenge Description

#### Points

1

#### Description

```
Category: Baby's First
Points: 1

mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me:21249
```

## Solution

On connection we get the following:

```shell
$ nc mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me 21249
2 - 1 =
1
3 - 2 =
1
1 + 1 =
2
1 + 2 =
3
You took too long!  You lost after 4 rounds.
```

Giving the right answer within a short time limit will yield more equations. The
complication in this challenge is that the given equations may come in the
following forms:

```
3 + 1 - 2 =
THREE - TWO =
2 + {2 - 1} =
1-(1+1)+2 =
3^2 - 2^3 =
```

To solve the equations, we can simply use Python eval :D. However, some of the
equations require some replacing of symbols to get them to run as python code.

Here is the solution:

```python
import socket

def main():
    s = socket.socket()
    s.connect(("mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me", 21249))
    while True:
        data = s.recv(9999)
        print data,
        if "won" in data:
            break
        statement = data[:data.index("=")-1]
        statement = statement.replace("[", "(").replace("]", ")")
        statement = statement.replace("{", "(").replace("}", ")")
        statement = statement.replace("^", "**")
        units = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
        "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
        "sixteen", "seventeen", "eighteen", "nineteen",]
        for i in units:
            statement = statement.replace(i.upper(), str(units.index(i)))
        result = eval(statement)
        print result
        s.sendall(str(result)+"\n")
    print "[Amon]: Bwahaha we solved it."

if __name__ == "__main__":
    main()
```

Here is it in action:

```shell
$ python mathwhiz.py
2 - 1 =
1
3 + 3 - 3 - 2 =
1
3 - 2 + 2 =
3
... SNIP ...
1 - 1 + 2 =
2
3 - 2 + 2 - 1 =
2
3 + 2 - 2 =
3
THREE - (ONE + ONE) =
1
3 - (1 - 1) - 1 =
2
3 + 3 - 3 - 1 =
2
2 + 2 - 1 =
3
You won!!!
The flag is: Farva says you are a FickenChucker and you'd better watch Super Troopers 2

[Amon]: Bwahaha we solved it.
```

Flag **Farva says you are a FickenChucker and you'd better watch Super Troopers
2**
