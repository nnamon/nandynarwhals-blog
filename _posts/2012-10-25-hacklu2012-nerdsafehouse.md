---
title: "Hack.lu CTF 2012 - Nerd Safehouse"
author: Nikolas
tags:
  - hacklu2012
  - writeup
  - web
---

*"Try solving the annoying puzzle at https://ctf.fluxfingers.net:2074/ or
zombies will eat your soul!"*

Upon entering the page specified in the puzzle, we were directed to a blank page
(https://ctf.fluxfingers.net:2074/?cid=vp3E1nOGh7jwP) as seen above. Our first
instinct was to view the source of this page for any clues. Taking a look at the
source, we found the following script:

```javascript
<script>history.replaceState(0,0,'?cid=vp3E1nOGh7jwP');</script>
```

By then, it was quite obvious that the redirection was caused by that line of
code. Hence, we decided to disable javascript in our browser to prevent the
redirection. We then loaded the page: "https://ctf.fluxfingers.net:2074/" once
again. This time we entered a similar page as the one above.

However, we noticed that the url for this page differed slightly. Instead of
"https://ctf.fluxfingers.net:2074/?cid=vp3E1nOGh7jwP", it was now
"https://ctf.fluxfingers.net:2074/?cid=vp3E1nOGh7iwP".

We then proceeded to check the source for this page and found the following:

```javascript
<script> location.href = atob('P2NpZD12cDNFbG5PR2g3andQ'); </script>
```

From this script, we can see that the atob() method was being used to decode a
string encoded in base64 (P2NpZD12cDNFbG5PR2g3andQ). We then decoded the base64
string and got the following:

```
?cid=vp3ElnOGh7jwP
```

All that was left was to replace the cid parameter with the new one and reload
the page. We were once again faced with the same blank page, except that the
flag was present in the source this time as a comment:

```html
<!-- The secret is 14574e443ef2331439d25dc9da3b617e :D -->
```

Flag: **14574e443ef2331439d25dc9da3b617e**.



