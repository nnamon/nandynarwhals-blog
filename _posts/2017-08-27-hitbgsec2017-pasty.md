---
title: "HITBGSEC CTF 2017 - Pasty (Web)"
header:
  overlay_image: /assets/images/hitbgsec2017/pasty/header.jpg
  overlay_filter: 0.5
  caption: "Photo credits: Rebecca Li on Unsplash"
tags:
  - hitbgsec2017
  - writeup
  - web
---

JSON Web Tokens have no means of authenticating the header and thus can be
abused to manipulate the server into verifying a forged signed message with a
key of the attacker's choosing.

## Challenge Description

#### Points

512

#### Description

```
Can you find the administrator's secret message?


http://47.74.147.52:20012
```

## Solution

First, we visit the website and we see that it is basically a pastebin. There is
authentication on the pastes if you turn on private mode.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/1.png){: .align-center}

If we register an account and login, a token is passed back for authorisation.
This token turns out to be a [JSON Web Token](https://jwt.io/introduction/).

![2]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/2.png){: .align-center}

The token is passed to the server in an `Authorization: Bearer` header. It is
used to authenticate a user statelessly by checking that the signature attached
to the message is properly signed. If we call the API to get a list of pastes,
we can see the token in use to retrieve  the list of pastes created by the user.


![3]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/3.png){: .align-center}

We can create a public paste like so on the site.

![4]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/4.png){: .align-center}

Repeating the API call shows that the paste is now appended to the previously
empty list.

![5]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/5.png){: .align-center}

We can use the debugger at this [website](https://jwt.io/) to analyse what is
going on in the JWT. Notice that there are three parts: the header, the content,
and the signature.

The vulnerability here is that the `kid` field that contains the path to the key
that is used to sign the message cannot be authenticated. Thus, if we can point
the `kid` to a location of our choosing, we can sign our own messages.

![6]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/6.png){: .align-center}

We can verify that it is using a URL path by checking if the `/keys/` directory
exists.

![7]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/7.png){: .align-center}

It seems like the application gets the content at `baseURL + kid + ".pem".
Next, we can grab the public key that signed our message.

```shell
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxfDcwRnQSGHehhz45TTt
cY+7xyBxqh9qHB3k2oczUMiE/BVrqm37B/it9ZcjD/Fsw9F4mqYXiCh4snnq37dB
vPQTsKbELHSeLG+nArN+gZ9ybMrx82MR63JfGkhyJe+S7/5698/11zqx2z2d8TbE
8lDpXY2Ll92wm3vE2PcLwwAUfdGiHk0c4oIHlsdwJ+9kEtuRZHF+ZurVvPkvgNHO
iw3bs8IkvICe26unWkov3g+0Ro4JNtqDN/szLKFD6g4vybhga/WBxU8eZ1uYMMEm
0Wr+1zq3/IY+KUIO9gbp9er9OLfSyrjalb3jos99DT4EEh9wzd+b4/uzPo+lUPDA
lQIDAQAB
-----END PUBLIC KEY-----
```

It is a simple PEM file. After quickly checking that the public key is secret
and we cannot get the private key from weak cryptography, we can generate our
own keys to sign content we want to forge.

```shell
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcNXBa2UAFnTStgn+96UXtv0zA
ZJ/u3o1W17JHJhdT1zgFBxaUlDWNAZ6BQakZKL89Jcf7lvULfBHr5w+HGLaySSuT
310Oco3+nroHV70/qYQsWUN34nOJeF7lat5jvLryxIr+r/0u3VwJyo+uVdmfHh0u
vaR8yEMXiE8VEmlnJQIDAQAB
-----END PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCcNXBa2UAFnTStgn+96UXtv0zAZJ/u3o1W17JHJhdT1zgFBxaU
lDWNAZ6BQakZKL89Jcf7lvULfBHr5w+HGLaySSuT310Oco3+nroHV70/qYQsWUN3
4nOJeF7lat5jvLryxIr+r/0u3VwJyo+uVdmfHh0uvaR8yEMXiE8VEmlnJQIDAQAB
AoGAFCmFngRKki7vXLHqYQ3Z+8zkUDTsu704Cwx+M1bETgsKbQO0M2tJ2jBqUA60
j83FmVPmEyAx8tCJ06QYSfyzn+3UQPBo0KS4kU7le36T77+k5sO1yeaE7cbLa5mS
reY56baHJAFSfHKgjtXqXMPO+0K33qE3x5fgSM2WLfsezKECQQDNCjAmez8wVPuK
xkmrNnBkUMOk0+5T9S3UydeevKqEHfmsDaulvz6VdU9Q82I1H2zBkxXIzay2epz1
o+iinwgJAkEAwwhWmRUa10uAkTB32prlEqQRb7C06kIQWfmjZAQzwuxyeD+CijZC
M3khPGlX1a5kTjiGx8tg+2wIe6N4LW3VPQJBALRRSGUfMEPuCMVTeogSuSbPjC8R
nl/BmAuxcmmMHB1SSzcPUqvSE1TXNOjJEc4ME9Xs51SP5FsaW5z/B+C0IRkCQQCt
r7NPSRhKO5cXtc5HBEKUw0Az825qYMMnHcaAv61JHkEjDYw3gfKa3HjY0AfE6DWz
42tEar7HqYI0eXQBIRsRAkEAiYgDyhEEj4aIu/wQU/bANcmC6ip4fQJinlk5zJ6K
DuGULHsf436INTiCFy9Wy5wyHMrUmPO4pMgrqcbo4DJ9/g==
-----END RSA PRIVATE KEY-----
```

Now, let's create a paste with the content of the public key.

![8]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/8.png){: .align-center}

The paste POST request returns a UUID that can be used to retrieve the paste. To
download the paste in raw form, we can append `?raw` to the URL.
![9]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/9.png){: .align-center}

Now, we can manipulate the server into using our paste as the signature file. We
modify the `kid` field to `/api/paste/5fb6891a-f0d5-43c4-a985-c9c4464c1a9e?raw&`
so that the final path would be
`<base_url>/api/paste/5fb6891a-f0d5-43c4-a985-c9c4464c1a9e?raw&.pem`. Next, we
change the `sub` field in the content portion to `admin` so that we can list the
private pastes in the admin account.

![10]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/10.png){: .align-center}

Calling the API to list the pastes with our forged token shows the private
paste created by the admin.

![11]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/11.png){: .align-center}

Now, we can retrieve the paste with the forged token to get our flag.

![12]({{ site.url }}{{ site.baseurl }}/assets/images/hitbgsec2017/pasty/12.png){: .align-center}

Flag: **HITB{b128a14885c4974c4a7016eb1d79aae6}**
