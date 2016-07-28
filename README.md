cryptam
=======

Cryptam document malware analysis tools to submit documents for analysis and collect reporting.

Get Report
----------
You can check for a https://repo.cryptam.com/reports/<sha256>.json or .html

### Example:
https://repo.cryptam.com/reports/f6999386343503b2536f864aaa3d6ab95bb2714263ca65d895c9e992cec8c0fc.json

Or search:
----------
Get or POST https://www.cryptam.com/docapirep.php

### Query Params:
hash: Any md5, sha1 or sha256
md5: md5
sha1: sha1
sha256: sha 256

A not found report will return json 'filename' "not found".


Upload file for analysis:
-------------------------
POST https://www.cryptam.com/docapi.php

### Query Params:
sample[]: File content:
message: note or email headers
email: your email address for report by emails


