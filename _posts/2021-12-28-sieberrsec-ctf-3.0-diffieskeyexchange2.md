---
title: "Sieberrsec 3.0 CTF (2021) - Diffie's Key Exchange 2 (Crypto)"
header:
  overlay_image: /assets/images/sieberrsec3.0/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sieberrsec 3.0 CTF Organisers"

tags:
  - sieberrsec
  - sieberrsec3.0
  - writeup
  - crypto
  - diffie hellman
  - small subgroup attack
---

Summary: Applying the small subgroup attack in a pseudo Diffie Hellman key exchange scheme that does
not give the public A value allows for an attacker to control the potential values of the shared
secret used to encrypt a flag sent back to the attacker. This makes it feasible to iterate through
the possible keys to decrypt the flag.

## Challenge Prompt

```console
Diffie's Key Exchange 2
Cryptography

Solves (4) - 895 Points

Diffie learnt that his implementation of the system wasn't secure :<< and made some changes. Try it now!
Connect here: nc challs.sieberrsec.tech 1338
chall.py
```

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/sieberrsec3.0/chall-diffie2.py)

## Solution

We are given a Python script that implements a pseudo form of the Diffie Hellman key exchange
scheme. The issue here is that only the generator `g` and the prime modulus `p` is given, not the
public key `A` computed by `g^a % p` which is typically required in the standard key negotiation
scheme to obtain the shared secret.

This 'shared' secret is used to encrypt the flag, thus our objective is to somehow control the value
of this secret without using the trivial values of `1` or `p-1`.

```python
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Util.Padding import pad


with open('flag.txt', 'rb') as f:
    flag = f.read()


g = 5
p = getPrime(512)
a = random.randrange(2, p - 1)
A = pow(g, a, p)

print("WELCOME TO DIFFIE'S KEY EXCHANGE!!!!!\n")
print(f'g: {g}', f'p: {p}', sep='\n')

B = int(input("\nWhat is your public key?\n"))


if not 1 < B < (p - 1):
    print('Sneakyyyyy....')
    exit()
else:
    shared_secret = pow(B, a, p)
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.encrypt(pad(flag, 16))
    print(f'\nencrypted flag: {enc.hex()}')
```

An example run of the program looks like:

```console
$ python chall.py
WELCOME TO DIFFIE'S KEY EXCHANGE!!!!!

g: 5
p: 7073777320102035715823648131537089890340861621438176702853737334100006916991407396992223330415000600499666889633196080596929221612545938856275346857404807

What is your public key?
12345

encrypted flag: 435d1960f90a1987cfdf8e8589773c65
```

Looking for previous CTF challenges involving [small subgroup confinement attacks](https://en.wikipedia.org/wiki/Small_subgroup_confinement_attack)
yields a challenge called [xorlnarmoni'akda](https://sasdf.github.io/ctf/tasks/2018/ais3Final/crypto/300-xorlnarmoni'akda/).

The important points from the writeup are:

* Factorising `p-1` gives us the sizes of the subgroups of the finite field over prime `p`.
* Generators for these subgroups can be computed by picking a random `r` that is not `1` or `-1` and
    evaluating `pow(r, (p-1) // subgroup_size, p)`.
* Our challenge gives the constraint that these generators must lie between `1` and `p - 1` exclusive
    so we have to reject the non-compliant generators.
* This generator will produce n elements of the subgroup size for any exponent used when computing
    `pow(g, a, p)`. Thus, we want to start with the smaller subgroups to reduce the AES key search
    space.

A Python script implementing this attack is given as follows:

```python
#!/usr/bin/env python

# With reference to https://sasdf.github.io/ctf/tasks/2018/ais3Final/crypto/300-xorlnarmoni'akda/.

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad

# pip install primefac
import primefac
import random
import hashlib


def main():
    # p = process(["python", "chall.py"])
    p = remote('challs.sieberrsec.tech', 1338)

    # Get g
    p.recvuntil(b'g: ')
    g = int(p.recvline().strip())
    log.info('generator = {}'.format(g))

    # Get p
    p.recvuntil(b'p: ')
    modulus = int(p.recvline().strip())
    log.info('prime modulus = {}'.format(modulus))

    # Check that p is prime and factor p-1.
    if not primefac.isprime(modulus):
        log.error("The provided modulus is not prime!")
        return
    log.info("The modulus is confirmed prime.")
    factors = primefac.primefac(modulus - 1)
    seen_factors = set()
    # Most likely 2 is a factor and thus provides a subgroup of size 2 but this generalises it.
    for factor in factors:
        if factor in seen_factors:
            continue
        seen_factors.add(factor)
        log.info('Testing subgroup size {}, if this is too big, please restart.'.format(factor))
        # Test 1000 integers.
        for i in range(1000):
            generator_candidate = random.randrange(2, modulus - 1)
            candidate = pow(generator_candidate, (modulus - 1) // factor, modulus)
            if candidate != (modulus - 1) and candidate != 1:
                log.info('Found candidate: {}'.format(candidate))
                # Find the possible shared values.
                possible_shared = set()
                ctr = 1
                while len(possible_shared) != factor:
                    possible_shared.add(pow(candidate, ctr, modulus))
                    ctr += 1
                log.info('Candidate has {} elements in subgroup: {}'.format(len(possible_shared),
                                                                            possible_shared))

                # Now that we have all we need to predict the possible shared secrets, send the
                # candidate.
                p.sendline(str(candidate).encode())
                p.recvuntil(b'encrypted flag: ')

                # Get the encrypted flag and try to decrypt it.
                encrypted_flag = p.recvline().strip().decode()
                log.info('Encrypted flag: {}'.format(encrypted_flag))
                for shared in possible_shared:
                    key = hashlib.md5(long_to_bytes(shared)).digest()
                    cipher = AES.new(key, AES.MODE_ECB)
                    try:
                        decrypted_flag = unpad(cipher.decrypt(bytes.fromhex(encrypted_flag)), 16)
                        if b'IRS{' in decrypted_flag:
                            log.success('Flag: {}'.format(decrypted_flag.decode()))
                            return
                    except:
                        pass

                return

    p.interactive()


if __name__ == '__main__':
    main()
```

Running the script gives us the flag:

```console
$ python exploit.py
[+] Opening connection to challs.sieberrsec.tech on port 1338: Done
[*] generator = 5
[*] prime modulus = 10825308872879721949075084480589739135613768878046508437798488882374928178964605436687265343911730293963921252288858056140801387959016711368887755373884633
[*] The modulus is confirmed prime.
[*] Testing subgroup size 2, if this is too big, please restart.
[*] Testing subgroup size 3, if this is too big, please restart.
[*] Found candidate: 2799472089545395126674853020489604564914518834747192924377242808839128120814339550917605237702625175135197994905931567052130656294583264910976368932597496
[*] Candidate has 3 elements in subgroup: {1, 2799472089545395126674853020489604564914518834747192924377242808839128120814339550917605237702625175135197994905931567052130656294583264910976368932597496, 8025836783334326822400231460100134570699250043299315513421246073535800058150265885769660106209105118828723257382926489088670731664433446457911386441287136}
[*] Encrypted flag: e9ab9fd773a30fc34ae628f1918941ee0ca00a3c2e4faba8a4fc9fc77af3bf2b
[+] Flag: IRS{5m411_5ubgr0up_4tt4cc}
```

**Flag:** `IRS{5m411_5ubgr0up_4tt4cc}`
