---
title: "STACK 2020 - Corrupted Hive (Forensics)"
header:
  overlay_image: /assets/images/stack-2020/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Steve Johnson"

tags:
  - stack
  - writeup
  - misc
  - registry
---

Summary: Data hdiden within a corrupt Windows registry hive contains an Base64-encoded guessable flag.

![Challenge description]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/2943DE39CECE9DB0AC79BB805DC07D15.jpg){: .align-center}

```
Corrupted Hive
2988
FORENSICS
4 SOLVES

DESCRIPTION
From intel sources, we discovered that the attacker likes to use registry to create persistency. From Forensic-challenge-2, we noted that the registry patch contains a specific key word. Search the registry hive and find the flag.

This challenge:
- Is eligible for Awesome Write-ups Award
- Prerequisite for Mastery Award - Forensicator
```

In this challenge, we are given a Windows registry hive.

```console
$ file forensics-challenge-3.hive
forensics-challenge-3.hive: MS Windows registry file, NT/2000 or above
```

Running floss on the hive turns up an interesting base64 encoded string.

```console
$ floss forensics-challenge-3.hive
...
@FirewallAPI.dll,-23505
@FirewallAPI.dll,-23506
importantkey
important
quasi-importantly
quas
Z3ZubHFvcC1zb3R7VzNuMTU3dXVfVTFhM30=
increaseinclusively
quasi-increased
quasi-independent
quasi-independently
quasi-indifferent
quasi-indifferently
quasi-induced
quasi-indulged
quasi-industrial
quasi-industrially
quasi-i
```

Decoding the base64 string reveals a flag-looking string.

```console
$ echo Z3ZubHFvcC1zb3R7VzNuMTU3dXVfVTFhM30= | base64 -d
gvnlqop-sot{W3n157uu_U1a3}
```

The interesting thing about this challenge is that it was the one that put us back up at third place in the last 30 minutes when a team member guessed the final password for this.

**Flag:** `govtech-csg{R3g157ry_H1v3}`
