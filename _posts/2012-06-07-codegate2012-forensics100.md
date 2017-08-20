---
title: "Codegate 2012: Forensics 100"
author: Hiromi
tags:
  - writeup
  - codegate
  - forensics
---

This was a CTF challenge solved by Hiromi in Codegate 2012.

## Description

```
In order to steal financial information of Company X, IU got a job under cover.
She decided to attack CFO’s computer, and then insert malicious code to his
computer in the way of social engineering. She figured out that he didn’t use to
turn off his computer, when he gets off work. After he leaves the office, she
obtains financial data from his computer to search EXCEL file. By checking
installed application program, she can find the information in the file. She
lacks the file externally. In order to remove all traces, she erases malicious
code, event logs and recent file list. The company X has to figure out what
information she stole correctly to make an appropriate measure. These are files
attacked from CFO’s computer. Find the full path and size of the file which she
stole. On the day, CFO left the office at 14:00. The time is based on Korea
Standard Time(UTC +09:00).

Answer: strlwr(md5(full_path|file_size))
('|' is just a character)
```

## Solution

We looked around a lot. Check folders, eliminated empty ones, etc. The simplest
way to find the stolen file is to grep for xls. `strings <bin file> | grep xls`
also helps to find xls strings in a bin file. Then we came across this:

```bash
yuuko@Sion:~/temp/short/Users/proneer/AppData/Local/Microsoft/Windows/History/History.IE5$
strings index.dat | grep xls
Visited: proneer@file:///C:/Data/xlsx/ITRC.xlsx
Visited: proneer@file:///C:/Data/xlsx/Result%20fo%20TESTSET.xlsx
Visited: proneer@file:///C:/Data/xlsx/
Visited:
proneer@file:///C:/Data/xlsx/080904_File%20Carving%20Results_DEASII_Final%20Forensics.xlsx
Visited: proneer@file:///C:/Data/xlsx/Book1.xlsx
Visited: proneer@file:///C:/Data/xlsx/Date.xlsx
Visited: proneer@file:///C:/Data/xlsx/dd.xlsx
Visited: proneer@file:///C:/Data/xlsx/LG%20CYON.xlsx
Visited:
proneer@file:///C:/Data/xlsx/Carving%ED%8C%8C%EC%9D%BC%EB%B6%84%EC%84%9D.xlsx
Visited:
proneer@file:///C:/INSIGHT/Accounting/Confidential/[Top-Secret]_2011_Financial_deals.xlsx
```

One file looks interesting: `Visited: proneer@file:///C:/INSIGHT/Accounting/Confidential/[Top-Secret]_2011_Financial_deals.xlsx`

```bash
yuuko@Sion:~/temp/short/Users/proneer/AppData/Local/Microsoft/Windows/History/History.IE5$
tree ../../../../../ | grep “Top-Secret”
[Top-Secret]_2011_Financial_deals.LNK
```

There it is, a shortcut file, looks like the thief forgot to remove it. Btw, we
could've did a tree -f that will print out the full path of the shortcut file.
`Users/proneer/AppData/Roaming/Microsoft/Office/Recent/[Top-Secret]_2011_Financial_deals.LNK`

Hmm, a shortcut file, let’s see what we can get out of it.

So we have the full path of the stolen file:
`C:INSIGHTAccountingConfidential[Top-Secret]_2011_Financial_deals.xlsx`. The
shortcut points to the same path too.

Googling "Lnk forensics" : http://www.forensicswiki.org/wiki/LNK

Metadata: "The size of the target when it was last accessed" sounds like what
we need.

The question asks for the the `md5(full_path|file_size)`, we're now able to get
the `file_size` part.

In the wiki page, "Free tool (in PERL) that is capable of reading and reporting
on Windows shortcut files"

Yea I like perl, lets check that tool out.

[lnk-parse-1.0.pl MS Windows LNK file parser](http://sourceforge.net/projects/jafat/files/lnk-parse/)

```bash
yuuko@Sion:~/temp/short/Users/proneer/AppData/Roaming/Microsoft/Office/Recent$
perl lnk-parse-1.0.pl [Top-Secret]_2011_Financial_deals.LNK

Link File: [Top-Secret]_2011_Financial_deals.LNK
Link Flags: HAS SHELLIDLIST | POINTS TO FILE/DIR | NO DESCRIPTION | HAS RELATIVE
PATH STRING | NO WORKING DIRECTORY | NO CMD LINE ARGS | NO CUSTOM ICON |
File Attributes: ARCHIVE
Create Time: Sun Feb 12 2012 13:39:49
Last Accessed time: Sun Feb 12 2012 13:39:49
Last Modified Time: Wed Jan 07 2009 12:17:41
Target Length: 9296
Icon Index: 0
ShowWnd: 1 SW_NORMAL
HotKey: 0
Target is on local volume
Volume Type: Fixed (Hard Disk)
Volume Serial: 8ce8c6c4
Vol Label:
Base Path: C:INSIGHTAccountingConfidential[Top-Secret]_2011_Financial_deals.xlsx
(App Path:) Remaining Path:
Relative Path:
INSIGHTAccountingConfidential[Top-Secret]_2011_Financial_deals.xlsx
```

There we have it. The filesize of the stolen file:

` Target Length: 9296`

```php
lowercase(md5(C:INSIGHTAccountingConfidential[Top-Secret]_2011_Financial_deals.xlsx|9296))
```

and we have the answer: **d3403b2653dbc16bbe1cfce53a417ab1**.

**Flag: d3403b2653dbc16bbe1cfce53a417ab1**
