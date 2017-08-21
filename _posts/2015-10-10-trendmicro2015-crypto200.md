---
title: "TrendMicro CTF 2015 - Crypto 200"
header:
  overlay_image: /assets/images/trendmicro2015/CBC_encryption.png
  overlay_filter: 0.5
tags:
  - trendmicro2015
  - writeup
  - cryptography
---

Recover the IV of an AES operation by utilising imperfect knowledge of the key
and encrypted output.

## Challenge Description

#### Points

200

#### Description

```
Zip Password: image_q

Your small program has been drew by kid, some values are missed, but you feel
you can restore it!

Please try to find the value of AES IV key.
```

## Solution

After extracting the ZIP file, we obtain this image:

![Question]({{ site.url }}{{ site.baseurl }}/assets/images/trendmicro2015/Q.png){: .align-center}

To make things a little clearer, let's transcribe what we can into a python
script:

```python
#!/usr/bin/env python

from Crypto.Cipher import AES
import sys
import binascii

KEY="5d619pfR7C1JQtXX"
target = "fe100000000000000000000000009ec3307df037c689300bbf2812ff89bc0b49"
IV="\x00"*16

def encrypt(message, passphrase):
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    return aes.encrypt(message)

def decrypt(message, passphrase):
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    return aes.decrypt(message)

if len(sys.argv) < 2:
    print "Please input your data!"
    sys.exit()

print "encrypted Data: " + binascii.hexlify(encrypt(sys.argv[1], KEY))
```

So let's take inventory of what we are missing:

1. 2 bytes out of 16 from the key
2. 25 out of 64 hexadecimal digits from the ciphertext
3. the entire 16 bytes of the IV.

Okay, so our objective is to recover the IV from what information we have. Some
important observations we have to make before we begin are:

- The plaintext message is exactly 32 bytes long. This means there will be two
  full ciphered blocks with no padding required. Indeed, the output is 32 bytes
  long.
- There are 100 x 100 possible keys (10000) assuming the key is within the set of
  printable characters.
- We have an uncorrupted full ciphered block. This is the second block of the
  cipher text: 307df037c689300bbf2812ff89bc0b49.
- Our corrupted ciphered block is: fe100000000000000000000000009ec3.
- We definitely need to recover the uncorrupted key and the uncorrupted first
  block to recover the cipher.
- Since the IV is always only used in XOR operations, we can safely set it to
  all zeroes. This effectively means that anything XOR'd with the IV will be
  itself. i.e. 0xdeadbeef ^ 0 == 0xdeadbeef.

Now that we have our basic observations, we can refresh our understanding of the
CBC decryption process. Taken from Wikipedia:

![CBC Decryption]({{ site.url }}{{ site.baseurl }}/assets/images/trendmicro2015/CBC_decryption.png){: .align-center}

If we pay attention to what's going on in reverse during the CBC operation, we
can see that the output of the decryption of the last block operation is the XOR
of the previous block's cipher text and the current block's plain text. Now this
can be expressed like so:

```shell
plaintext_n = decrypt(key, ciphertext_n) ^ ciphertext_n-1
ciphertext_n-1 = decrypt(key, ciphertext_n) ^ plaintext_n
```

This gives us a way to do recover our key and first block of cipher text since
we know that the full plain text of block two ("rotected by AES!") and some
digits of the cipher text of the previous block. Our sketch to do this is like
so:

```shell
For all possible keys:
    decrypted_block = decrypt(lastblock, key)
    current_block = xor(decrypted_block, "rotected by AES!")
    if current_block starts with fe1 and ends with 9ec3:
        we have found our full key and ciphertext block
```

Now, once we have that we have the key and first cipher text block, all that is
left to be done is decrypt that cipher text block with the key and we would get
the XOR of the plain text and the IV. Simply XOR with the plain text to retrieve
the IV.

Here is the full script:

```python
#!/usr/bin/env python

from Crypto.Cipher import AES
import sys
import binascii
import itertools
import string

KEY="5d6I9pfR7C1JQtXX"
target = "fe100000000000000000000000009ec3307df037c689300bbf2812ff89bc0b49"
IV="\x00"*16
plain = "The message is protected by AES!"

def encrypt(message, passphrase):
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    return aes.encrypt(message)

def decrypt(message, passphrase):
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    return aes.decrypt(message)

def xor(thing1, thing2):
    res = []
    for i in range(len(thing1)):
        res.append( chr(ord(thing1[i]) ^ ord(thing2[i])))
    return "".join(res)

last_block = target[32:].decode("hex")
last_plain = plain[16:]
mutable_key = list(KEY)
REAL_KEY = None
REAL_BLOCK = None
for i in itertools.product(string.printable, string.printable):
    mutable_key[-2] = i[0]
    mutable_key[-1] = i[1]
    newkey = "".join(mutable_key)
    dec = decrypt(last_block, newkey)
    cur = xor(dec, last_plain).encode("hex")
    if cur[:3] == "fe1" and cur[28:32] == "9ec3":
        print "Found real key: %s (%s)" % (newkey, cur)
        REAL_KEY = newkey
        REAL_BLOCK = cur

real_dec = decrypt(REAL_BLOCK.decode("hex"), REAL_KEY)
REAL_IV = xor(real_dec, plain[:16])
print "IV: %s" % REAL_IV
print "Here's your flag: TMCTF{ %s }" % REAL_IV[4:]
```

Running it:

```shell
$ python cr.py
Found real key: 5d6I9pfR7C1JQt7$ (fe1199011d45c87d10e9e842c1949ec3)
IV: Key:rVFvN9KLeYr6
Here's your flag: TMCTF{rVFvN9KLeYr6}
```

Flag: **TMCTF{rVFvN9KLeYr6}**


