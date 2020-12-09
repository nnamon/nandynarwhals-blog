---
title: "STACK 2020 - The Suspicious Frequency Monitoring Alert (IOT)"
header:
  overlay_image: /assets/images/stack-2020/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Steve Johnson"

tags:
  - stack
  - writeup
  - iot
  - wlan
---

Summary: Malformed IEEE 802.11 RSN tags within select beacon frames are used as a means of encoding hidden data.

![Challenge description]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/resources/97EF0AC2CBFF2C85583D9379873FFDDB.jpg){: .align-center}

```
The suspicious frequency monitoring alert!
995 INTERNET OF THINGS
9 SOLVES

DESCRIPTION
We received an alert from our smart city’s frequency monitoring and noticed some anomalies. Figure out what is happening!

This challenge:
- Is eligible for Awesome Write-ups Award
```

We are provided with a PCAP file:

```console
$ file iot-challenge-2.pcap
iot-challenge-2.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11 with radiotap header, capture length 262144)
```

The PCAP file contains IEEE 802.11 wireless packets.

![Wireless packets]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/resources/4C5FC0F9AD0AC65F147CABB7CEAB923E.jpg){: .align-center}

Checking the protocol hierarchy confirms that only wireless packets are contained within the capture.

![Protocol hierarchy]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/resources/B4F966507FFD104B47E0E1747C4B378B.jpg){: .align-center}

Running aircrack on the PCAP file turns up two access points that require no encryption.

```console
$ aircrack-ng iot-challenge-2.pcap
Opening iot-challenge-2.pcap
Read 14096 packets.

   #  BSSID              ESSID                     Encryption

   1  00:26:75:E0:EC:20  SINGTEL-EC1F              WPA (0 handshake)
   2  88:C3:97:60:FE:40  Blessed_r_u_5G_plus       WPA (0 handshake)
   3  A8:5E:45:F0:19:E8                            WPA (0 handshake)
   4  88:1F:A1:39:E7:0E  Zodiac                    WPA (0 handshake)
   5  76:4F:57:92:0D:F6  sabrelab_Guest            No data - WEP or WPA
   6  74:DA:88:D5:20:97  TP-Link_2098_             No data - WEP or WPA
   7  4C:1B:86:73:2F:AC  SINGTEL-2FAC              WPA (0 handshake)
   8  70:4F:57:92:0D:F6  sabrelab                  WPA (0 handshake)
   9  7A:4F:57:92:0D:F6                            No data - WEP or WPA
  10  D8:0D:17:B4:1B:C4                            WPA (0 handshake)
  11  30:23:03:41:23:A7  Linksys14325              No data - WEP or WPA
  12  D0:05:2A:77:38:22  SINGTEL-3820              WPA (0 handshake)
  13  74:DA:88:92:0D:4B  TP-Link_1491_             None (0.0.0.0)
  14  DE:0D:17:B4:1B:C4  Rahman                    WPA (0 handshake)
  15  24:F5:A2:42:B6:39  Maillot                   No data - WEP or WPA
  16  BC:30:D9:75:3C:46  SINGTEL-3C46              No data - WEP or WPA
  17  D4:63:FE:BA:C8:C1  SINGTEL-C8BF              WPA (0 handshake)
  18  D0:03:4B:D8:2D:F1                            Unknown
  19  1A:59:C0:56:FE:AD  ORBI22                    No data - WEP or WPA
  20  D0:03:4B:D8:2D:F0                            Unknown
  21  F0:D1:A9:12:69:B2  Zodiac                    No data - WEP or WPA
  22  48:8D:36:97:FF:EB                            Unknown
  23  E0:51:63:9C:BB:5E  SINGTEL-BB5E              No data - WEP or WPA
  24  1E:59:C0:56:FE:AD                            No data - WEP or WPA
  25  26:F5:A2:42:B6:39  Maillot-invité           None (0.0.0.0)
```

We can search for packets with the source address of 74:DA:88:92:0D:4B (`TP-Link_1491_`) using the following filter:

```
wlan.sa == 74:DA:88:92:0D:4B
```

This turns up a small number of beacon frames.

![Filtered beacon frames]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/D5ADAE28B962A3CAA29209A7E92F88AA.jpg){: .align-center}

Checking the packets reveals that the packets contain malformed RSN tags with some interestingly formatted data.

![Malformed RSN tags]({{ site.url }}{{ site.baseurl }}/assets/images/stack-2020/B91FD828E053E78BDF47F5F0FDDE7359.jpg){: .align-center}

Collecting all of the unique fragments yields:

```
1:Z292dGVjaC1j
2:c2d7SW9UX1dp
3:RmlfRXhmaWx0
4:cmF0aW9OIX0=
```

Putting the fragments together and decoding it as base64 gives us the flag:

```console
echo Z292dGVjaC1jc2d7SW9UX1dpRmlfRXhmaWx0cmF0aW9OIX0= | base64 -d
govtech-csg{IoT_WiFi_ExfiltratioN!}
```

**Flag:** `govtech-csg{IoT_WiFi_ExfiltratioN!}`
