---
title: "CTF(x) 2016 - Custom Auth (Crypto)"
header:
  overlay_image: /assets/images/ctfx2016/customauth/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sam Ferrara on Unsplash"
tags:
  - ctfx2016
  - writeup
  - cryptography
---

A cookie using ECB mode encryption allows an attacker to forge admin privileges
by rearranging encrypted blocks for decryption.

## Solution

Here's our solution:

```python
import requests

host = "http://problems.ctfx.io:7001/"
#host = "http://localhost:3000/"
evil_params = {'username': 'AAAAAAAAAAAAAAA', 'password':'BBBBBBBBBBB',
               'dmin':1, 'a':1}

def chunk(d, sz):
    return [d[i:i+sz] for i in range(0, len(d), sz)]

def main():
    s = requests.Session()
    s.post(host + "login", data=evil_params)
    auth = s.cookies.get("auth")
    auth_chunks = chunk(auth, 32)
    reveal = "".join((auth_chunks[0], auth_chunks[1], auth_chunks[4]))
    s.cookies.set("auth", reveal)
    flag_text = s.get(host).text
    for i in flag_text.split("\n"):
        if "Flag" in i:
            print i

if __name__ == "__main__":
    main()
```

Running the script:

```shell
amon@Evanna:~/ctf/ctfx/crypto/customauth$ python exploit.py
        <span><b>Flag: </b><code>ctf(ecb_m0de_too_Ez?)</code></span>
```


Flag: **ctf(ecb\_m0de\_too\_Ez?)**
