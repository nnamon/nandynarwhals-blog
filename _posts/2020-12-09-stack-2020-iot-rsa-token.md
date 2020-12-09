---
title: "STACK 2020 - IOT RSA Token (IOT)"
header:
  overlay_image: /assets/images/stack-2020/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Steve Johnson"

tags:
  - stack
  - writeup
  - iot
  - lcd
  - i2c
---

Summary: An I2C trace of a probed 16x2 LCD screen is provided in which credentials containing a usernames, passwords, and a SecurID key can be extracted.

![Challenge description]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/4FDEDA8E865982D5DD3A75106A7A12EF.jpg =642x815)

```
IOT RSA Token
3000 INTERNET OF THINGS
0 SOLVES

DESCRIPTION
We were able to get our hands on a RSA token that is used as 2FA for a website. From the token, we sniffed some data (capture.logicdata) and took some photos of the token. Lastly, we found a key written at the back of the token, the contents of which we placed into key.txt. Unfortunately, we dropped the token in the toilet bowl and it is no longer working. Using the data sniffed and the photos (rsa_token_setup.png and welcome_msg.png) taken, make sense of the data that is displayed on the rsa token, help us predict what the next rsa token will be!

Login Page (http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:40551/)

This challenge:
- Unlocks other challenge(s)
- Is eligible for Awesome Write-ups Award
- Prerequisite for Mastery Award - IoT Crypto Expert
```

Full writeup to be completed...

```python
#!/usr/bin/env python

'''
IOT RSA Token Solver
'''


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def main():
    data = open('./dump.bin', 'rb').read()

    print('Got {} bytes of data.'.format(len(data)))

    data = data[1:]
    print('Ignoring the initial pull low, have {} bytes of data.'.format(len(data)))

    print('Extracting higher bits from the 4 bit transmission stream.')

    result = ''.join(i[0] for i in chunks(data.hex(), 2))[::2]

    result = (len(result) % 2) * '0' + result

    open('decoded.bin', 'wb').write(bytes.fromhex(result))

    print('Written decoded stream to decoded.bin.')


if __name__ == '__main__':
    main()
```
