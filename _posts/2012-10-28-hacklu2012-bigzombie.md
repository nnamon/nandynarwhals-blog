---
title: "Hack.lu CTF 2012 - Big Zombie Business"
tags:
  - hacklu2012
  - writeup
  - web
---

*It's a disaster! Not only that these useless piles of rotten meat obfuscate all
their stupid code, they have also lost our precious root password, or "Flag" as
they call it. Is there a chance you can reverse this obfuscation to extract the
Flag?*

At first look, the source code is a mess. Let's begin deobfuscating the first
script tag (using python and jsbeautifier.org):

```javascript
(function () {
    if (typeof console == undefined) console = {
        'log': function () {}
    };
    setInterval((function () {
        var c = console.log;
        var u = function () {
            c('%cBraaaaAAAINZZZZ', 'color:red;font-size:200px;')
        };
        u(), u(), u();
        return u
    })(), 100);
    f = function () {
        location = 'noflag'
    };
    n = {
        value: f,
        configurable: false
    };
    (a = document.addEventListener)('DOMAttrModified', f, false);
    a('DOMNodeInserted', f, false);
    a('DOMCharacterDataModified', f, false);
    for (i in m = ['write', 'writeln', 'createElement', 'appendChild',
        'cloneNode', 'insertBefore', 'replaceChild', 'createElementNS'])
        Object.defineProperty(document.constructor.prototype, m[i], n);
        var y = alert;
        Object.defineProperty(window, 'alert', {
            value: function () {
                y('braaainzzz')
            },
            configurable: false
        });
        var z = prompt;
        Object.defineProperty(window, 'prompt', {
            value: function (q) {
                brain(z('What's my zombie name ? '), q)
            },
            configurable: false
        });
        for (i in m = ['confirm ', 'console'])
            Object.defineProperty(window, m[i], n);
})();
```

We can see that this is where the the prompt we encounter on window open and the
alert when we click on the picture of Charlie Sheen is defined. It's also
interesting to see that references to the console are made which mean we should
expect to see something appear on the javascript debug console.

The second script tag is deobfuscated:

```javascript
with(new XMLHttpRequest()) {
    open('GET', '?i=31', false);
    send();
    if (status == 200) eval(responseText)
}
```

We can see that a request is made to https://ctf.fluxfingers.net:2076/big/?i=31
and the received is eval'd. Let's see that this is:

```shell
amon@Alyx:~/hacklu$ curl -k https://ctf.fluxfingers.net:2076/big/?i=31
u0066u006cu0061u0067="x77x72x6fx6ex67x66x6cx61x67"
```

Deobfuscated this is:

```javascript
flag="wrongflag"
```

:/ But then we notice that the script tag has a 'src' attribute defined.

Note: this blog post is incomplete in conversion since the images are missing.
