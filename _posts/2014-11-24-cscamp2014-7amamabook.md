---
title: "CSCAMP CTF 2014 - 7amama Book (Web)"
tags:
  - cscamp2014
  - writeup
  - web
---

Insecure direct object reference allows changing of password of another user.

## Challenge Description

#### Points
300

#### Description

```
7amamaBook is a social media website where people can sign up and share with
each other. It has a bug bounty program and you found a bug and reported it but
they refuse to pay you so you want to give them a payback by hacking it.
```

## Solution

Quite a tricky challenge with the CSRF decoy :P

Of course, since the challenge description mentions that you submitted a bug
bounty report but they didn't accept it and they do mention it on their site as
well, looks like it wouldn't be a CSRF vulnerability.

On visiting the site we are faced with:

So we sign up for an account:

Now in our account, we can see that there are links to the founders. Let's take
a look at Zuckerberg:

And look, there's a private post! Of course we gotta read the private post!

So, let's update our account. Which lets us specify the username, by the way :D.
So we just fill in Zuckerberg's account name and change the password to
something we know.

Relogging in...

And hooray, we get to read the post:

We try that weird string in our challenge submission box and it gets accepted!
Great, 300 points!

Flag: **askdhakjsdas**

Note: there are missing images in this post.
