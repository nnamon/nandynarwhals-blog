---
title: "QIWICTF 2014 - Stolen Prototype (Misc100)"
author: Hiromi
tags:
  - qiwictf2014
  - writeup
  - misc
---

**This is a stolen application of super-duper payment system.  But this is
broken piece of cake, completely broken =(**

We're faced with an  Android apk, so DECOMPILE! Decompiled with this
wonderful [website](http://www.decompileandroid.com/).

After decompiling, we have a bunch of files but all we need is the .java files.

```java
private String d;

private String a()
    {
        StringBuilder stringbuilder;
        DefaultHttpClient defaulthttpclient;
        UsernamePasswordCredentials usernamepasswordcredentials;
        HttpGet httpget;
        Character character = Character.valueOf('n'); //note this
        String s = d.substring(0, 1); //note this
        Log.d(getPackageName(), s);
        stringbuilder = new StringBuilder();
        defaulthttpclient = new DefaultHttpClient();
        String s1 = (new StringBuilder()).append(s).append("vty").toString(); //note this
        Log.d(getPackageName(), (new StringBuilder()).append(character).append("s").append(s1).append("f").append(character).append("j").append(s).toString());
        usernamepasswordcredentials = new UsernamePasswordCredentials("xxx", (new StringBuilder()).append(character).append("s").append(s1).append("f").append(character).append("j").append(s).toString()); //note this
        httpget = new HttpGet((new StringBuilder()).append("https://qiwictf2014.ru:54321/account?key=").append("").append("&account=").append("afgssdfgsdgsfgdfbxcbsdbkjnkwej").toString());
        BufferedReader bufferedreader;
        httpget.addHeader(BasicScheme.authenticate(usernamepasswordcredentials, "UTF-8", false));
        HttpResponse httpresponse = defaulthttpclient.execute(httpget);
        if (httpresponse.getStatusLine().getStatusCode() != 200)
        {
            break MISSING_BLOCK_LABEL_350;
        }
...

protected void onCreate(Bundle bundle)
    {
        super.onCreate(bundle);
        StrictMode.setThreadPolicy((new android.os.StrictMode.ThreadPolicy.Builder()).permitAll().build());
        Random random = new Random();
        String s = (new StringBuilder()).append("ctf201").append("444444".charAt(random.nextInt("444444".length()))).toString(); //note this
        d = (new StringBuilder()).append("https://qiwi").append(s).append(".ru:").append("40443").toString(); //note this
        setContentView(0x7f030000);
        b = (TextView)findViewById(0x7f080003);
        c = (Button)findViewById(0x7f080008);
        c.setOnClickListener(new a(this));
        Log.d(getPackageName(), (new StringBuilder()).append("Init for:https://qiwictf2014.ru:54321").append(a()).toString());
    }
```

Above is an excerpt of one of the .java files. Accounts.java. Here we see the
stuff we need. I've marked them out with //note this. I piece the strings
together manually and got:

```
Target URL: https://qiwictf2014.ru:40443

Username: xxx

Password: nshvtyfnjh
```

```python

import requests

r = requests.post('https://qiwictf2014.ru:40443', auth=('xxx','nshvtyfnjh'))
print r.status_code
print r.headers
print r.text
print r.json()
```

Above is the script to solve it. Note that its a POST and not GET. Using GET
will just give you a No Method Error.

With POST you get the flag,

```json
{"welldone": "ZN2014_3db056df7036e11c823707f5adf923e9"}
```

Flag: **ZN2014\_3db056df7036e11c823707f5adf923e9**

