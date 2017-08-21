---
title: "DEFCON CTF Qualifiers 2015 - Access Control (Reversing)"
tags:
  - defconquals2015
  - writeup
  - reversing
---

Reverse engineer a server binary to determine how to interact with it and write
a client.

## Challenge Description

#### Points

1

#### Description

```
Category: Reverse Engineering
Points: 1

It’s all about who you know and what you want.
access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me:17069
```

## Solution

The solution script:

```python
import struct
import socket
import time
import telnetlib

def generate_password(username, connectionid, index=1):
    # Part 1 sub_8048EAB
    connectmod = ord(connectionid[7]) % 3
    connectindex = connectmod+index
    connectseed = connectionid[connectindex:connectindex+5]
    xoredname = ""
    for i in range(len(connectseed)):
        xoredname += chr(ord(connectseed[i]) ^ ord(username[i]))

    # Part 2 sub_8048F67
    password = ""
    for i in xoredname:
        iv = ord(i)
        if iv <= 0x1f:
            password += chr(ord(i) + 0x20)
        elif iv == 0x7f:
            password += chr(ord(i) - 0x7e + 0x20)
        else:
            password += i

    return password

def parse_connection_id(data):
    return data[15:len(data)-1]

def parse_challenge(data):
    return data[-14:-9]

def main():
    name = "duchess" # is the administrator

    # Make connection
    server = ("52.74.123.29", 17069)
    version = "version 3.11.54"

    s = socket.socket()
    s.connect(server)

    connectionid = parse_connection_id(s.recv(9999))

    # What is your version?
    s.send(version + "\n")

    # What is your name?
    s.send(name + "\n")

    # What is your password
    s.send(generate_password(name, connectionid) + "\n")

    # Print key
    s.send("print key\n")
    data = recv_timeout(s)
    challenge = parse_challenge(data)
    s.send(generate_password(challenge, connectionid, 7))

    # Print key again
    s.send("print key\n")

    print recv_timeout(s)

    print "[Amon]: Congratulations, there's your flag! Handing the session over to you. Have fun interacting!"
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()


def recv_timeout(the_socket,timeout=1):
    #make socket non bloc + "\n"king
    the_socket.setblocking(0)

    #total data partwise in an array
    total_data=[];
    data='';

    #beginning time
    begin=time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break

        #if you got no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break

        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin = time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass

    #join all parts to make final string
    return ''.join(total_data)

if __name__ == "__main__":
    main()
```
