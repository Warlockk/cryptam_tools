#!/usr/bin/python
import requests
import sys
import json
import os.path


cryptam_url = "https://cryptam.com/docapi.php"


def cryptam(filename):
   submitted_file={'sample[]': open(filename, 'rb')}
   c=requests.post(cryptam_url,files=submitted_file) #might need a verify=False for ssl with self signed cert
   return c.text
   id=json.loads(c.text)
 


if len(sys.argv) > 1:
   r = cryptam(sys.argv[1])
   print r
   try: 
      j = json.loads(r)
      print "sample ID " + j['id']
   except:
      None