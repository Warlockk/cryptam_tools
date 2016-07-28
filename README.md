cryptam
=======

Cryptam document malware analysis tools to submit documents for analysis and collect reporting. Default reporting is now returned only in JSON which is served from fast flat files.

Get Report
----------
You can check for a report with the document sha256 at https://repo.cryptam.com/reports/ **sha256**.json or **sha256**.html

### Example:

https://repo.cryptam.com/reports/f6999386343503b2536f864aaa3d6ab95bb2714263ca65d895c9e992cec8c0fc.json

Or search by any hash:
---------------------
GET or POST https://www.cryptam.com/docapirep.php

### Query Params:

hash: Any md5, sha1 or sha256

md5: md5

sha1: sha1

sha256: sha256

A not found report will return json 'filename' "not found".

### Example:

https://www.cryptam.com/docapirep.php?sha256=f6999386343503b2536f864aaa3d6ab95bb2714263ca65d895c9e992cec8c0fc

Upload file for analysis:
-------------------------
POST https://www.cryptam.com/docapi.php

### Query Params:

sample[]: File content

message: note or email headers

email: your email address for report by emails

Pulling dropped file strings:
----------------------
drop_files field has a line per dropped file, get the strings link by changing s3://mwstore/samples/ to https://repo.cryptam.com/nodes/ and add .txt 

### Example:

https://repo.cryptam.com/nodes/6260af28efd479034e30f124584072b01d4f30b0d7ad35232cdbb699b49dbefb.virus.txt
