---
title: "Hack.lu CTF 2015 - Creative Cheating (Crypto 150)"
header:
  overlay_image: /assets/images/hacklu2015/creativecheating/header.jpg
  overlay_filter: 0.5
tags:
  - hacklu2015
  - writeup
  - cryptography
---

Analyse a given PCAP for some secret communication between Alice and Bob and
determine which messages contain a valid signature.

## Challenge Description

#### Author

one

#### Points

150 (+60)

#### Description

```
Mr. Miller suspects that some of his students are cheating in an automated
computer test. He captured some traffic between crypto nerds Alice and Bob. It
looks mostly like garbage but maybe you can figure something out.

He knows that Alice's RSA key is (n, e) = (0x53a121a11e36d7a84dde3f5d73cf,
0x10001) (192.168.0.13) and Bob's is (n, e) = (0x99122e61dc7bede74711185598c7,
0x10001) (192.168.0.37)
```

## Solution

First, let's see if we can obtain the private key credentials for Alice and Bob.
The numbers seem small enough. After finding the prime factorisation of Alice's
and Bob's keys, we have the following values

```shell
bob's p = 49662237675630289
bob's q = 62515288803124247

alice's p = 38456719616722997
alice's q = 44106885765559411
```

Now, it is trivial to generate the private decryption keys for Alice and Bob.
Let's leave that to later though and continue with the other part of the
challenge.

We are given a PCAP file with only one stream inside. Following the stream and
viewing the data shows that there is a whole bunch of base64 encoded lines.

![Wireshark]({{ site.url }}{{ site.baseurl }}/assets/images/hacklu2015/creativecheating/1.png){: .align-center}

If we take one of the strings and decode it:

```python
In [2]: base64.decodestring("U0VRID0gMjg7IERBVEEgPSAweDE5Njg4ZjExMmE2MTE2OWM5MDkwYTRmOTkxOGRMOyBTSUcgPSAweDE0NDhhYzZlZWUyYjJlOTFhMGE2MjQxZTU5MGVMOw==")
Out[2]: 'SEQ = 28; DATA = 0x19688f112a61169c9090a4f9918dL; SIG = 0x1448ac6eee2b2e91a0a6241e590eL;'
```

There are three pieces of information in a line:

1. The sequence number,
2. The encrypted data,
3. and the signature of the encrypted data.

Now, there are multiple lines with the same sequence number. Hence, we can infer
that there must be some distinguishing feature of the signature that tells us
which one in the sequence is the right one.

Now, we must decrypt the data and the signature. To do this, we can use Bob's
decryption key to decrypt the data and Alice's public key to decrypt the
signature. Let's generate the parameters:

```shell
    bp = 49662237675630289
    bq = 62515288803124247

    ap = 38456719616722997
    aq = 44106885765559411

    bn = bp*bq
    an = ap*aq

    phb = (bp-1)*(bq-1)
    pha = (ap-1)*(aq-1)

    e = 0x10001

    ad = modinv(e, pha)
    bd = modinv(e, phb)

    print "Bob's Decryption Key:"
    print "Exponent: 0x%x  Modulus: 0x%x" % (bd, bn)
    print "Alice's Encryption Key:"
    print "Exponent: 0x%x  Modulus: 0x%x" % (e, an)
```

And running the code:

```shell
$ python generate.py
Bob's Decryption Key:
Exponent: 0x465b47fc6d267ca4f18f98c00ca1  Modulus: 0x99122e61dc7bede74711185598c7
Alice's Encryption Key:
Exponent: 0x10001  Modulus: 0x53a121a11e36d7a84dde3f5d73cf
```

So let's use the parameters to try decrypting the data and signature by hand.


```python
In [1]: bob_d = 0x465b47fc6d267ca4f18f98c00ca1

In [2]: bob_n = 0x99122e61dc7bede74711185598c7

In [3]: alice_e = 0x10001

In [4]: alice_n = 0x53a121a11e36d7a84dde3f5d73cf

In [5]: chr(pow(0x19688f112a61169c9090a4f9918d, bob_d, bob_n))
Out[5]: '\x0b'

In [6]: chr(pow(0x1448ac6eee2b2e91a0a6241e590e, alice_e, alice_n))
Out[6]: 'h'
```

Notice they don't match, so we can discard this line. Now, let's do this for the
rest of the lines and print out the ones that do match. That would be our flag.

```python
import base64

data = """U0VRID0gMTM7IERBVEEgPSAweDNiMDRiMjZhMGFkYWRhMmY2NzMyNmJiMGM1ZDZMOyBTSUcgPSAweDJlNWFiMjRmOWRjMjFkZjQwNmE4N2RlMGIzYjRMOw==
... snip ...
U0VRID0gMjQ7IERBVEEgPSAweDc1YzFmYmMyOGJiMjdiNWQyZGI5NjAxZmI5NjdMOyBTSUcgPSAweDJiNWI2MjhiZjgxODM0MDBjZGFiN2Y1ODcwYjFMOw=="""

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def main():

    # Crypto part
    bp = 49662237675630289
    bq = 62515288803124247

    ap = 38456719616722997
    aq = 44106885765559411

    bn = bp*bq
    an = ap*aq

    phb = (bp-1)*(bq-1)
    pha = (ap-1)*(aq-1)

    e = 0x10001

    ad = modinv(e, pha)
    bd = modinv(e, phb)

    # Parse part
    lines = [base64.decodestring(i) for i in data.split("\n")]
    seqs = {}
    for i in lines:
        parts = i.split(";")
        seq_no = int(parts[0][6:])
        if not seq_no in seqs.keys():
            seqs[seq_no] = []
        dint = int(parts[1][8:-1], 16)
        sint = int(parts[2][7:-1], 16)
        seqs[seq_no].append((dint, sint))

    flag = ""
    for i in seqs.keys():
        for j in seqs[i]:
            dec_data = pow(j[0], bd, bn)
            dec_sig = pow(j[1], e, an)
            if dec_data == dec_sig:
                c = chr(dec_data)
                print "Found sequence %d: %s" % (i, c)
                flag += c

    print "Flag is: %s" % flag

if __name__ == "__main__":
    main()
```

And running it:

```shell
$ python solve.py
Found sequence 0: f
Found sequence 1: l
Found sequence 2: a
Found sequence 3: g
Found sequence 4: {
Found sequence 5: n
Found sequence 6: 0
Found sequence 7: t
Found sequence 8: h
Found sequence 9: 1
Found sequence 10: n
Found sequence 11: g
Found sequence 12: _
Found sequence 13: t
Found sequence 14: 0
Found sequence 15: _
Found sequence 16: 5
Found sequence 17: 3
Found sequence 18: 3
Found sequence 19: _
Found sequence 20: h
Found sequence 21: 3
Found sequence 22: r
Found sequence 23: 3
Found sequence 24: _
Found sequence 25: m
Found sequence 26: 0
Found sequence 27: v
Found sequence 28: 3
Found sequence 29: _
Found sequence 30: 0
Found sequence 31: n
Found sequence 32: }
Flag is: flag{n0th1ng_t0_533_h3r3_m0v3_0n}
```

The flag is: **flag{n0th1ng\_t0\_533\_h3r3\_m0v3\_0n}**
