---
title: "Hack.lu CTF 2012 - Mini Zombie Business"
tags:
  - hacklu2012
  - writeup
  - web
---

*As time passes by and the zombie apocalypse seems to stay for a while businesses
have to adapt to survive. Food store chains offer brains and biscuits for their
limping customers and fox on Fire seems to be a all-time-zombie-favourite, too.
Since a lot of zombies have a broad band connection businesses strive to get
online stores back up again. It's just that webdesign seems to be quite hard for
zombie employees. They obfuscate all their code (god knows why).*

*Here is an example of a miserable attempt to create a working website.*

If we look at the source, we can see that there is a custom data attribute in a
form tag (data-a) that contains encrypted data which we can assume is decrypted
by the obfuscated javascript.

It is interesting to note that opening the site in Chrome yields errors from
running the javascript so we have to use Firefox ('fox on Fire', lol) to run the
code successfully.

After the code is run, it writes data to the div tag in the data-a attribute
which creates the function dafuq. It's then trivial to see that the function
spawns a prompt that takes the string 'tasty brainz' and then prints the flag
`tasty_humans_all_day_erry_day`. The function can be called by clicking on the
image.

Flag: **tasty\_humans\_all\_day\_erry\_day**
