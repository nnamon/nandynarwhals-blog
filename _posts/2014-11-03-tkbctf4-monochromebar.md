---
title: "TKBCTF 4 - Monochrome Bar"
author: Hiromi
tags:
  - tkbctf4
  - writeup
  - steganography
---

The only steganography challenge in TKBCTF4 and its only worth 100 points.

At first I thought it was morse code... Didn't work out quite well going that
route.

In the end it was decided that its a MANYpx by MANYpx image rearranged into
MANYMANYpx by 1px image.

The code to piece the image back is as below.

```python
#! /usr/bin/python2

from sys import argv
from PIL import Image

im = Image.open(argv[1])
imageW = im.size[0]
imageH = im.size[1]
pixels = im.load()

brute = [100, 108, 135, 150, 162, 180, 225, 243, 270, 300, 324,
        405, 450, 486, 540, 675, 729]


for width in brute:
    out_w = width
    out_h = im.size[0]/width
    img = Image.new(im.mode,
                    (out_w, out_h),
                    None
                    )
    #y=height x=width
    print '[+] Processing image size: {} x {}'.format(out_w, out_h)

    h_count = 0
    w_count = 0
    for px in range(imageW):

        if w_count == out_w:
            #new height row
            #print "w_count={}, h_count={}".format(w_count,h_count)
            w_count = 0
            h_count += 1

        img.putpixel((w_count, h_count),pixels[px,0])
        w_count+=1

    print "Writing {}x{}".format(str(out_w), str(out_h))
    img.save('output_{}x{}.png'.format(str(out_w), str(out_h)), 'PNG')
```

Guess a few widths, and rearrange the pixels by the guesstimated widths.

![The assembled image]({{ site.url }}{{ site.baseurl }}/assets/images/tkbctf4/qrcode.png){: .align-center}
The assembled image
{: .text-center}

I tried scanning it with the QR Code scanner from my phone but it didn't work...

So I found this [ZXing Decoder Online](http://zxing.org/w/decode.jspx) which
decodes a bunch of barcodes and QR code that you can upload.

It spits out some Base64.

```
RkxBR3tDaDF0M2sxazBrMXNoMW4tbTRufQ==
```

Decoding it produces the flag.

Flag: **FLAG{Ch1t3k1k0k1sh1n-m4n}**


