---
title: "PoliCTF 2015 - It's Hungry (Forensics 100)"
header:
  overlay_image: /assets/images/polictf2015/pulseboy.png
  overlay_filter: 0.7
tags:
  - polictf2015
  - writeup
  - forensics
---

A troll challenge that required you to transcribe a melody on a hidden area of
the website.

## Challenge Description

#### Points

100

#### Description

```
Old McDonald had a farm. Old McDonald liked chiptune. He also needed to remind
its daughter to take care about a zombie animal. But he wanted to do it
discreetly, so he wrote this song. Can you find the message? (all lowercase, no
spaces) N.B. flag is not in format flag{.+}
```

## Solution

This was the Hidden Challenge in the Scoreboard. If you clicked on the numbers
in the music control at the top left of the screen, it'll show.

![Hidden challenge]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/hiddenchallenge.png){: .align-center}

The description is obviously referring to the chiptune music that's being played
in the background. So let's download it and examine it.

```shell
$ wget http://polictf.it/tunes/oldmcdonald.flac
$ file oldmcdonald.flac
oldmcdonald.flac: FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz, 6323646 samples
```

Great, it's a FLAC file and there doesn't seem to be anything immediately
striking on a first listen. Maybe there's something in the metadata tags.

```shell
$ metaflac --list oldmcdonald.flac
METADATA block #0
  type: 0 (STREAMINFO)
  is last: false
  length: 34
  minimum blocksize: 4096 samples
  maximum blocksize: 4096 samples
  minimum framesize: 3729 bytes
  maximum framesize: 14093 bytes
  sample_rate: 44100 Hz
  channels: 2
  bits-per-sample: 16
  total samples: 6323646
  MD5 signature: 74cf7c267ccb4fbec7c6a38297808d8b
METADATA block #1
  type: 4 (VORBIS_COMMENT)
  is last: true
  length: 168
  vendor string: reference libFLAC 1.3.0 20130526
  comments: 7
    comment[0]: GENRE=Chiptune
    comment[1]: TRACKNUMBER=0
    comment[2]: ALBUM=PoliCTF15
    comment[3]: Flag=Yeah, dream on!
    comment[4]: TITLE=oldmcdonald
    comment[5]: DATE=2015
    comment[6]: ARTIST=rbino
```

Haha, there's nothing in here and we got trolled. So maybe let's take a look in
Audacity. Very often, CTFs will hide images visible when viewing the audio in a
spectrogram. And there are three images!

![Keep listening]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/keeplistening.png){: .align-center}
<small>*We should keep listening...*</small>
{: .text-center}

![Morse]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/morse.png){: .align-center}
<small>*Translates to: YOUAREOVERCOMPLICATINGJUSTLISTEN*</small>
{: .text-center}

![Troll]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/troll.png){: .align-center}
<small>*Getting trolled*</small>
{: .text-center}

Okay, looks like all signs are telling us to LISTEN. So that's what we did. For
hours.

Then, I thought, what if I transcribed the notes in the melody? There could be a
message in there right? So I fired up [PulseBoy](http://www.pulseboy.com/) and
spent about half an hour matching notes by ear.

![Fiddling]({{ site.url }}{{ site.baseurl }}/assets/images/polictf2015/fiddling.png){: .align-center}

I finally managed to get a piece that matched. It had the following notes
(number is the octave):

```
    F4 E4 E4 D4 D4 A4 D4 E4 A4 D4 B3 E E4 F4
```

So our message was: feeddadeadbeef.

We submitted that and got our 100 points :)

Flag: **feeddadeadbeef**
