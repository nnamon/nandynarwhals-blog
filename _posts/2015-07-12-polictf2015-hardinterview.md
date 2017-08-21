---
title: "PoliCTF 2015 - Hard Interview (Grab Bag 50)"
header:
  overlay_image: /assets/images/polictf2015/swordfish.jpg
  overlay_filter: 0.5
tags:
  - polictf2015
  - writeup
  - misc
---

Simulated shell environment lets you pretend to be Hugh Jackman in Swordfish.

## Challenge Description

#### Points

50

#### Description

```
interview.polictf.it:80
```

## Solution

This one was pretty funny and we were the first team to solve it :D (yay 8
breakthrough points!). Let's connect to the service to check it out.


```shell
$ nc interview.polictf.it 80

<... massive ascii art snip ...>

fish@sword:~$ help
 A very hard interview: Codename Blow...Fish
Maybe you can help me with something...
DOD d-base, 128 bit encryption....What do you think?
Maybe slide in a Trojan horse hiding a worm...
I have been told that best "crackers" in the world can do it 60 minutes, unfortunately i need someone who can do it in 60 seconds... naturally with the right incentives ;)
If you know what I mean, tell me how a real cracker accesses to a remote super protected server...

Possible commands:
      hacker: Write code as a real hacker
        help: Give informations about the program
        hint: Gives a little hint
        exit: Loser...bye Bye
         ssh: A tiny ssh command
        date: A very useful and innovative feature

fish@sword:~$ hint
 usage:  ssh username@address
    username: THE username
    address: a not so easily reachable IP address
Very simple...isn't it?
fish@sword:~$ date
Sun Jul 12 14:25:15 CEST 2015
 fish@sword:~$ exit
 Loser...bye Bye
```

After a huge ASCII art display, we are dropped into a shell. Nothing normal (ls,
cat, id, etc) is available however we can use the command 'help' to list what we
can do. Here's a summary of the commands:

- hacker - basically a version of HackerTyper on the terminal except it's going by
  itself
- help - this help
- hint - tells you to use ssh, presumably to get the flag
- exit - exits the shell, and insults you in the process
- ssh - what we are supposed to use to get the flag
- date - prints the 'current' date (not really)

Now our first lead is the 'briefing' at the start of the help: *"DOD d-base, 128
bit encryption.... I have been told that best "crackers" in the world can do it
60 minutes, unfortunately i need someone who can do it in 60 seconds... e right
incentives"*. What does this sound like? The movie Swordfish, of course. I mean,
the name's right there in the prompt.

So we go on Youtube and look for a
[video](https://www.youtube.com/watch?v=zfy5dFhw3ik) from the hacking scene
where Hugh Jackman is forced at gunpoint to perform an impossible hack.

Now, since we are told to 'ssh' into a system. Let's look out for usernames and
ip addresses. Right before the point where Hugh is successful, the scene focuses
on these two screens:

![IP Addresses]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/ipadd.png){: .align-center}
![Usernames]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/user.png){: .align-center}

So, '**admin**' stands out like a sore thumb and for the IP address... what do we
have here? **312.5.125.233**? That does look like a not so reachable IP...

```shell
fish@sword:~$ ssh admin@312.5.125.233
 flag{H4ll3_B3rry's_t0pl3ss_sc3n3_w4s_4ls0_n0t4bl3}
```

Success :)

Flag: **flag{H4ll3\_B3rry's\_t0pl3ss\_sc3n3\_w4s\_4ls0\_n0t4bl3}**
