---
title: "Sieberrsec 3.0 CTF (2021) - Digging in the Dump (Forensics)"
header:
  overlay_image: /assets/images/sieberrsec3.0/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sieberrsec 3.0 CTF Organisers"

tags:
  - sieberrsec
  - writeup
  - forensics
---

Summary: The PHP function realpath can be tricked to allow other protocol wrappers to be used in
readfile by specially crafting the directories in an unzipped zip file.

## Challenge Prompt

Part 1:

```
Digging In The Dump Pt. I
Forensics

Solves (31) - 266 Points

Our friend, Alex, used to visit a website, but ever since his computer died the url to the website was lost!
The only hope now lies in his old hard drive, which was salvaged from his pc
Hopefully something useful can be found

Here is a dump of his %APPDATA% folder
Can you help him find the website?
```

Attachment: [challenge file]({{ site.url }}{{ site.baseurl }}/assets/files/sieberrsec3.0/AppData.zip)

Part 2:

```
Digging In The Dump Pt. II
Forensics

Solves (9) - 292 Points

After finding that website, perhaps you can find the saved credentials to login to his account?
(Using the same file in Pt. I)

Computer username: Alex
Computer password: Password1
(These are NOT the login credentials for the website)
```


## Solution

### Part 1

We are given a large 250MB zip file containing a Windows user's Application Data directory.

```console
$ file AppData.zip
AppData.zip: Zip archive data, at least v2.0 to extract
$ find AppData | head
AppData
AppData/LocalLow
AppData/LocalLow/Microsoft
AppData/LocalLow/Microsoft/CryptnetUrlCache
AppData/LocalLow/Microsoft/CryptnetUrlCache/Content
AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/6BADA8974A10C4BD62CC921D13E43B18_AD319D6DA1A11BC83AC8B4E4D3638231
AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/80237EE4964FC9C409AAF55BF996A292_C5130A0BDC8C859A2757D77746C10868
AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/57C8EDB95DF3F0AD4EE2DC2B8CFD4157
AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/77EC63BDA74BD0D0E0426DC8F8008506
AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/E0968A1E3A40D2582E7FD463BAEB59CD
...
```

We can look for a few browsers to look for browser history artifacts. To start with, Google Chrome
[stores the visited URLs](https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location)
in the `History` file. This file is present in the dump:

```console
$ find AppData | grep Chrome | grep History
AppData/Local/Google/Chrome/User Data/Default/History-journal
AppData/Local/Google/Chrome/User Data/Default/History
```

The file can be opened with the `sqlite3` program and the correct table can be identified using the
`.schema` command.

```console
$ sqlite3 'AppData/Local/Google/Chrome/User Data/Default/History'
SQLite version 3.32.3 2020-06-18 14:16:19
Enter ".help" for usage hints.
sqlite> .schema
...
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
...
```

Selecting from the table yields a pertinent URL with the `challs.sieberrsec.tech` domain name.

```console
sqlite> select * from urls;
1|https://www.google.com/search?q=bing&oq=bing&aqs=chrome..69i57j0i433i512j46i433i512j0i131i433i512j0i512j0i131i433i512l3j46i433i512j46i512.1018j0j7&sourceid=chrome&ie=UTF-8|bing - Google Search|2|0|13284792092515784|0
2|http://www.bing.com/|Bing|1|0|13284792132998452|0
3|https://www.bing.com/|Bing|1|0|13284792132998452|0
4|https://www.bing.com/search?q=google&form=QBLH&sp=-1&pq=google&sc=8-6&qs=n&sk=&cvid=E0635C87D5F44F3A8C498FEAB34156BB|google - Search|1|0|13284792153017298|0
5|http://www.google.com.sg/|Google|1|0|13284792155381137|0
6|https://www.google.com.sg/?gws_rd=ssl|Google|2|0|13284792155754230|0
7|https://www.google.com.sg/search?q=cookies+near+me&source=hp&ei=NE_FYfmVGPWO4-EPz8KI6Ac&iflsig=ALs-wAMAAAAAYcVdRA0CQ1NwjvY3j8cWR4dLEAdaR-_Y&ved=0ahUKEwj5_8Sez_v0AhV1xzgGHU8hAn0Q4dUDCAk&uact=5&oq=cookies+near+me&gs_lcp=Cgdnd3Mtd2l6EAMyCAgAEIAEEMkDMgUIABCSAzIFCAAQgAQyBQgAEIAEMgUIABCABDIFCAAQgAQyBQgAEIAEMgUIABCABDIFCAAQgAQyBQgAEIAEOg4ILhCPARDqAhCMAxDlAjoOCAAQjwEQ6gIQjAMQ5QI6CAgAELEDEIMBOg4ILhCABBCxAxDHARDRAzoUCC4QgAQQsQMQgwEQxwEQrwEQ1AI6CAgAEIAEELEDOgUIABCxAzoUCC4QgAQQsQMQxwEQowIQ1AIQiwM6EQgAEIAEELEDEIsDEKYDEKgDOg4IABCABBCxAxCDARCLAzoOCC4QsQMQgwEQxwEQowI6DgguEIAEELEDEMcBEKMCOgsIABCABBCxAxCDAToICC4QgAQQsQM6CwguEIAEELEDENQCOg4ILhCxAxCDARDHARCvAToRCC4QgAQQsQMQgwEQxwEQowI6DgguEIAEEMcBEK8BEIsDOggIABCABBCLAzoLCC4QgAQQxwEQrwFQqE5Ysl5g2WRoBHAAeACAAYoBiAHGBpIBBDE0LjGYAQCgAQGwAQq4AQI&sclient=gws-wiz|cookies near me - Google Search|2|0|13284792170964074|0
8|https://www.google.com.sg/search?q=Best+butter+cookies+in+Singapore&sa=X&ved=2ahUKEwjinbylz_v0AhVr7XMBHQjTBCsQ1QJ6BAgcEAE&biw=988&bih=620&dpr=1|Best butter cookies in Singapore - Google Search|3|0|13284792739005609|0
9|https://www.lifestyleasia.com/sg/food-drink/dining/best-cookies-in-singapore-delivery/|7 best cookies in Singapore by local bakers to try this weekend|1|0|13284792304156059|0
10|https://www.theweddingvowsg.com/best-cookie-shops-singapore/|7 Best Cookie Shops in Singapore | Best of Lifestyle 2021|1|0|13284792743089170|0
11|http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190|Flag|1|0|13284792773737661|0
12|http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190/|Flag|2|0|13284792797469196|0
sqlite>
```

Retrieving the webpage gives us the flag along with a login form:

```console
$ curl 'http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190/'
<!DOCTYPE html>
<html>
    <head>
        <Title>Login</Title>
        ...
    </head>
    <body>
        <div class="topnav">
            <h1>Login Page</h1>
        </div>
        <br><br>
        <div class="login">
            <p>IRS{D1ggiNg_1N_tH3_chR0M3_h15t0rY}</p>
            <form method="post" class='loginform'>
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>

                <input type="submit" name="submit" value="Login">
            </form>
        </div>
    </body>
</html>
```


**Flag:** `IRS{D1ggiNg_1N_tH3_chR0M3_h15t0rY}`


### Part 2

In the second part, we are supposed to login to the webpage, presumably using saved login
credentials. The version of Google Chrome used in this challenge is relatively new:

```console
$ cat 'AppData/Local/Google/Chrome/User Data/Last Version'
96.0.4664.110
```

According to [Foxton Forensics](https://www.foxtonforensics.com/blog/post/analysing-chrome-login-data),
the file containing the saved credential data is `Login Data`. From the schema, it appears that the
pertinent table is `logins`.

```console
$ sqlite3 'AppData/Local/Google/Chrome/User Data/Default/Login Data'
SQLite version 3.32.3 2020-06-18 14:16:19
Enter ".help" for usage hints.
sqlite> .schema
...
CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, form_data BLOB, display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR, skip_zero_click INTEGER, generation_upload_status INTEGER, possible_username_pairs BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, moving_blocked_for BLOB, date_password_modified INTEGER NOT NULL DEFAULT 0, UNIQUE (origin_url, username_element, username_value, password_element, signon_realm));
...
sqlite>
```

There is an entry for the site but the password is encrypted.

```console
sqlite> select * from logins;
http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190/|http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190/|username|Alex24|password|v10���/F��n�dCJ��9ނ\||http://challs.sieberrsec.tech:23547/|13284792800298041|0|0|0|0|�||||0|0||1|13284792797426951||13284792800298530
sqlite>
```

Decrypting this value differs according to Google Chrome version. The pertinent pull request for
the decryption scheme is given in [Chromium 1842671](https://chromium-review.googlesource.com/c/chromium/src/+/1842671).
We can observe that this change occured first in [version
80.0.3948.0](https://github.com/chromium/chromium/commit/265b39473af0faac989b44afb6d4eb5cb2fd2e24).

The `password_value` blob is encrypted with a wrapped AES key in GCM mode. This wrapped key is
itself encrypted using the [Windows Data Protection API](https://en.wikipedia.org/wiki/Data_Protection_API)
with the [`CryptProtectData` call](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

The wrapped key is stored in the `Local Data` JSON file in the `os_crypt.encrypted_key` field.

```console
$ cat 'AppData/Local/Google/Chrome/User Data/Local State' | jq -r .os_crypt.encrypted_key
RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAABzlbQ33sJ6SIG+uML5tN8VAAAAAAIAAAAAABBmAAAAAQAAIAAAAK3K+lbEQhgKWXCUhfBo0B3IclDK4Trudr1YXLSpiVrZAAAAAA6AAAAAAgAAIAAAAI8CLxksWgwYvM4vJvniv+XVLtpiEjhmLvA/iNiLLrJ7MAAAAA4T0R9gdcrWpucsGmwbEFAMUGY30fRbTVyNUqLHgDT/qIqALJL3l0xcj0qgEVilWEAAAAB+xquYwbQPWjx7gsQOB1svow83EbccXe8sxn1gNotgQeISqaJkDdiRxWmVuEJg4tJmqLENgBs1ZJuzFtYb7fQ3
```

If we decode the base64, we can confirm that it syncs up with what is expected from the Chromium
[source code](https://github.com/chromium/chromium/blob/f95c449bb79a961ae3332f6783f770159a3e1189/components/os_crypt/os_crypt_win.cc#L36).
The `DPAPI` prefix is present and should be removed prior to running an `CryptUnprotectData` call.

```console
$ cat 'AppData/Local/Google/Chrome/User Data/Local State' | jq -r .os_crypt.encrypted_key | base64 -d | xxd
00000000: 4450 4150 4901 0000 00d0 8c9d df01 15d1  DPAPI...........
00000010: 118c 7a00 c04f c297 eb01 0000 0073 95b4  ..z..O.......s..
00000020: 37de c27a 4881 beb8 c2f9 b4df 1500 0000  7..zH...........
00000030: 0002 0000 0000 0010 6600 0000 0100 0020  ........f......
00000040: 0000 00ad cafa 56c4 4218 0a59 7094 85f0  ......V.B..Yp...
00000050: 68d0 1dc8 7250 cae1 3aee 76bd 585c b4a9  h...rP..:.v.X\..
00000060: 895a d900 0000 000e 8000 0000 0200 0020  .Z.............
00000070: 0000 008f 022f 192c 5a0c 18bc ce2f 26f9  ...../.,Z..../&.
00000080: e2bf e5d5 2eda 6212 3866 2ef0 3f88 d88b  ......b.8f..?...
00000090: 2eb2 7b30 0000 000e 13d1 1f60 75ca d6a6  ..{0.......`u...
000000a0: e72c 1a6c 1b10 500c 5066 37d1 f45b 4d5c  .,.l..P.Pf7..[M\
000000b0: 8d52 a2c7 8034 ffa8 8a80 2c92 f797 4c5c  .R...4....,...L\
000000c0: 8f4a a011 58a5 5840 0000 007e c6ab 98c1  .J..X.X@...~....
000000d0: b40f 5a3c 7b82 c40e 075b 2fa3 0f37 11b7  ..Z<{....[/..7..
000000e0: 1c5d ef2c c67d 6036 8b60 41e2 12a9 a264  .].,.}`6.`A....d
000000f0: 0dd8 91c5 6995 b842 60e2 d266 a8b1 0d80  ....i..B`..f....
00000100: 1b35 649b b316 d61b edf4 37              .5d.......7
```

First, we can extract the DPAPI encrypted data without the prefix into a file called `blob`:

```python
In [4]: import json, base64

In [5]: x = json.load(open('AppData/Local/Google/Chrome/User Data/Local State', 'rb'))['os_crypt']['encrypted_key']

In [6]: x = base64.b64decode(x)

In [7]: open("blob",'wb').write(x[5:])
Out[7]: 262
```

Next, we need to decrypt this blob with DPAPI. According to [HackTricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords),
the DPAPI master keys can be found in the `AppData/Roaming/Microsoft/Protect/` directory under the
user's SID. These master keys are, of course, themselves protected by the user's computer password.

Looking in the `Protect` directory yields the following files, also conveniently letting us know the
user's SID. `37b49573-c2de-487a-81be-b8c2f9b4df15` is the master key file.

```console
$ find AppData/Roaming/Microsoft/Protect/
AppData/Roaming/Microsoft/Protect/
AppData/Roaming/Microsoft/Protect//S-1-5-21-1937579505-2679969469-2152769792-1001
AppData/Roaming/Microsoft/Protect//S-1-5-21-1937579505-2679969469-2152769792-1001/Preferred
AppData/Roaming/Microsoft/Protect//S-1-5-21-1937579505-2679969469-2152769792-1001/37b49573-c2de-487a-81be-b8c2f9b4df15
AppData/Roaming/Microsoft/Protect//CREDHIST
```

The decrypted master key can be extracted from this file using Mimikatz with the user's password.
The final `key :` field contains the master key that can be used with other Mimikatz commands.

From the challenge prompt, we are given the user's computer password: `Password1`.

```console
mimikatz # dpapi::masterkey /in:37b49573-c2de-487a-81be-b8c2f9b4df15 /sid:S-1-5-21-1937579505-2679969469-2152769792-1001 /password:Password1 /protected
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {37b49573-c2de-487a-81be-b8c2f9b4df15}
  dwFlags            : 00000005 - 5
  dwMasterKeyLen     : 000000b0 - 176
  dwBackupKeyLen     : 00000090 - 144
  dwCredHistLen      : 00000014 - 20
  dwDomainKeyLen     : 00000000 - 0
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 0eab1ddb63fd2af7084ce8d9f9e63627
    rounds           : 00001f40 - 8000
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 5c84f8625f8a4c9c787de1e9f6b32d132b658794d9f7640e3454b29ac5f5b36e6bfd4f86bf1d919bac543a252d5a94185e4dd49b1590e335675457e9f76ad91d9a0b25072b1b4b3bb9ef60b776cc6dfabfe3e683dc4cfb442016b508651290ad1d29b2cba2d972f73445c7a4788ffdca21aa3f341776aaf5f8b5b42cbb417da70d93a2f185b458a6e5b089f4b0c93412

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : b48c96813ad38e18d0c844b5e04011bc
    rounds           : 00001f40 - 8000
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 3a7434ac385f98dae77dfef87387bdab92ad5d68e2f100e2738fc0b359425437903a60e1cb84979b93217e204af73876ea26feb2c1e104467a05a5052c95446d8f0b31767a2e4e411cb0a11fa0a39c1e12e43ad7d68069bfe5a06baef4727bac962a0326ad1e1c9e051206321c2e6a30

[credhist]
  **CREDHIST INFO**
    dwVersion        : 00000003 - 3
    guid             : {3a0a76a2-7cde-4675-ba7d-b3e858d5f9ad}



[masterkey] with password: Password1 (protected user)
  key : 907de0d2d2f63f6478cfd2433dbf1c868a440246f415d709598fd5cfaceb422cb878944803a6b20a02ec593af2e5bceca5c8fae4cb175680b867ab8f1b45067f
  sha1: 6f76fc2c00dbd0c024a7779ad27d9397c1f833da

mimikatz #
```

The previously dumped `os_crypt` blob can now be decrypted with another Mimikatz command using the
extracted master key.

```console
mimikatz # dpapi::blob /masterkey:907de0d2d2f63f6478cfd2433dbf1c868a440246f415d709598fd5cfaceb422cb878944803a6b20a02ec593af2e5bceca5c8fae4cb175680b867ab8f1b45067f /in:"blob" /out:blob.dec
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {37b49573-c2de-487a-81be-b8c2f9b4df15}
  dwFlags            : 00000000 - 0 ()
  dwDescriptionLen   : 00000002 - 2
  szDescription      :
  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : adcafa56c442180a59709485f068d01dc87250cae13aee76bd585cb4a9895ad9
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : 8f022f192c5a0c18bcce2f26f9e2bfe5d52eda621238662ef03f88d88b2eb27b
  dwDataLen          : 00000030 - 48
  pbData             : 0e13d11f6075cad6a6e72c1a6c1b10500c506637d1f45b4d5c8d52a2c78034ffa88a802c92f7974c5c8f4aa01158a558
  dwSignLen          : 00000040 - 64
  pbSign             : 7ec6ab98c1b40f5a3c7b82c40e075b2fa30f3711b71c5def2cc67d60368b6041e212a9a2640dd891c56995b84260e2d266a8b10d801b35649bb316d61bedf437

 * volatile cache: GUID:{37b49573-c2de-487a-81be-b8c2f9b4df15};KeyHash:6f76fc2c00dbd0c024a7779ad27d9397c1f833da
 * masterkey     : 907de0d2d2f63f6478cfd2433dbf1c868a440246f415d709598fd5cfaceb422cb878944803a6b20a02ec593af2e5bceca5c8fae4cb175680b867ab8f1b45067f
description :
Write to file 'blob.dec' is OK

mimikatz #
```

To do the final decryption of the Chrome login credentials, we can adapt [this Python
script](https://github.com/ohyicong/decrypt-chrome-passwords/blob/main/decrypt_chrome_password.py)
to use the manually dumped Chrome `os_crypt` key.

```python
#Full Credits to LimerBoy
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

def get_secret_key():
    secret_key = open('blob.dec', 'rb')
    return secret_key

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        return sqlite3.connect(chrome_path_login_db)
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    secret_key = get_secret_key()
    chrome_path_login_db = "Login Data"
    conn = get_db_connection(chrome_path_login_db)
    if(secret_key and conn):
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for index,login in enumerate(cursor.fetchall()):
            url = login[0]
            username = login[1]
            ciphertext = login[2]
            if(url!="" and username!="" and ciphertext!=""):
                decrypted_password = decrypt_password(ciphertext, secret_key)
                print("Sequence: %d"%(index))
                print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                print("*"*50)
        cursor.close()
        conn.close()
```

Running the script gives us:

```console
$ python decrypt_chrome_password.py
Sequence: 0
URL: http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190/
User Name: Alex24
Password: IHeartCookies

**************************************************
```

Logging into the site with the decrypted Chrome credentials gives us our flag:

```console
$ curl 'http://challs.sieberrsec.tech:23547/dcfa237943d4fd7e2a514ca54642efaccd2cdbd5003bfb19a1e70737273e1190/' \
    --data 'username=Alex24&password=IHeartCookies&submit=Login'

<!DOCTYPE html>
<html>
    <head>
        <title>Flag</title>
        ...
    </head>
    <body>
        <div class="topnav">
            <h1>Flag</h1>
        </div>
        <br><br>
        <div class="flagbox">
            <p>IRS{aL1_uR_p45sw0rD_4r3_b3LOnG_t0_u5}</p>
        </div>
    </body>
</html>
```

**Flag:** `IRS{aL1_uR_p45sw0rD_4r3_b3LOnG_t0_u5}`
