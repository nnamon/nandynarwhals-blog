---
title: "Codegate 2012: Forensics 200"
author: Hiromi
tags:
  - writeup
  - codegate
  - forensics
---

This was a CTF challenge solved by Hiromi in Codegate 2012.

## Description

```
When IU who lives in Seoul tried to do SQL Injection attack a certain WEB site,
suddenly the browser was closed abnormally. What is the SQL Injection value she
tried to enter and when the browser was closed? The time is based on Korea
Standard Time(UTC +09:00)
Time Format is YYYY-MM-DDThh:mm:ssTZD (TZD : +hh:mm or hh:mm)

Answer : injection_value|time
('|' is just a character)
Convert ' ' to '_' for injection value.
```

## Solution

So we check out the folders of the various browsers. Found an interesting link
to http://docbe.com/2012/01/05/web-browser-session-restore-forensics-3/

So we decided to see if that helps. First up Firefox Recovery: Mozilla Session
Restore.

Followed the instructions in the pdf from the above link, and there it is:
C:UsersUserNameAppDataRoamingMozillaFirefoxProfiles########.defaultsessionstore.js

According to the document, sessionstore.js is created when the browser force
restarts. sessionstore.js will be deleted when the browser shuts down normally.
So we took a look at the sessionstore.js which is in json.
http://jsoneditor.net/ < Using this makes things easier. I cat-ed the file
though.

And look what we found (excerpt, full one at the bottom of the post):

```javascript
formdata":{"//xhtml:li[@id='search-3']/xhtml:div/xhtml:form/xhtml:fieldset/xhtml:input[@name='s']":"1_UNI/**/ON_SELECT"}[/javascript]
>1_UNI/**/ON_SELECT
```

```
<Hiromi> well lets see
<Hiromi> "1_UNI/**/ON_SELECT"
<Hiromi> does that smell like sqli?
<amon> OHH
<amon> yes
```

There we found the sqli. Now for the timing since Answer :
`injection_value|time`

There are 4 epoch/unix timestamps in the file. We converted them to Time Format
is YYYY-MM-DDThh:mm:ssTZD (TZD : +hh:mm or hh:mm) and tried them out.

`1_UNI/**/ON_SELECT|2012-02-12T10:23:17+09:00`

And there we have the answer.

## Addendum

```javascript
{"windows":[{"tabs":[{"entries":[{"url":"about:home","title":"Mozilla Firefox Start Page","ID":0,"docshellID":5,"owner_b64":"NhAra3tiRRqhyKDUVsktxQAAAAAAAAAAwAAAAAAAAEYAAQAAAAAAAS8nfAAOr03buTZBMmukiq45X+BFfRhK26P9r5jIoa8RAAAAAAVhYm91dAAAAARob21lAODaHXAvexHTjNAAYLD8FKM5X+BFfRhK26P9r5jIoa8RAAAAAA5tb3otc2FmZS1hYm91dAAAAARob21lAAAAAA==","docIdentifier":0},{"url":"http://forensic-proof.com/","title":"FORENSIC-PROOF","ID":2,"docshellID":5,"docIdentifier":2,"formdata":{"//xhtml:li[@id='search-3']/xhtml:div/xhtml:form/xhtml:fieldset/xhtml:input[@name='s']":"1_UNI/**/ON_SELECT"},"scroll":"0,0"}],"index":2,"hidden":false,"attributes":{"image":"http://forensic-proof.com/wp-content/uploads/2011/10/search.ico"}},{"entries":[{"url":"about:newaddon?id=toolbar@ask.com","title":"Install Add-on","ID":1,"docshellID":7,"owner_b64":"SmIS26zLEdO3ZQBgsLbOywAAAAAAAAAAwAAAAAAAAEY=","docIdentifier":1},{"url":"http://forensicinsight.org/","title":"Forensic Insight","ID":3,"docshellID":7,"docIdentifier":3,"formdata":[],"scroll":"0,0"}],"index":2,"hidden":false,"attributes":{"image":"http://forensicinsight.org/wp-content/uploads/2011/11/FilterFeather2.gif"}}],"selected":1,"_closedTabs":[],"busy":false,"width":994,"height":750,"screenX":4,"screenY":4,"sizemode":"maximized","cookies":[{"host":".forensic-proof.com","value":75300229,"path":"/","name":"__utmc"},{"host":".forensicinsight.org","value":12711840,"path":"/","name":"__utmc"}]}],"selectedWindow":1,"_closedWindows":[],"session":{"state":"running","lastUpdate":1329009797205,"startTime":1329009441160,"recentCrashes":0},"scratchpads":[],"lastSessionState":{"windows":[{"tabs":[{"entries":[{"url":"about:home","title":"Mozilla Firefox Start Page","ID":0,"docshellID":5,"owner_b64":"NhAra3tiRRqhyKDUVsktxQAAAAAAAAAAwAAAAAAAAEYAAQAAAAAAAS8nfAAOr03buTZBMmukiq45X+BFfRhK26P9r5jIoa8RAAAAAAVhYm91dAAAAARob21lAODaHXAvexHTjNAAYLD8FKM5X+BFfRhK26P9r5jIoa8RAAAAAA5tb3otc2FmZS1hYm91dAAAAARob21lAAAAAA==","docIdentifier":0,"formdata":[],"scroll":"0,0"}],"index":1,"hidden":false,"attributes":{"image":"chrome://branding/content/icon16.png"}}],"selected":1,"_closedTabs":[],"width":994,"height":750,"screenX":4,"screenY":4,"sizemode":"maximized","title":"Mozilla Firefox Start Page"}],"selectedWindow":1,"_closedWindows":[],"session":{"state":"stopped","lastUpdate":1328976025895,"startTime":1328975220425,"recentCrashes":0},"scratchpads":[]}}
```
