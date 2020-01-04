#!/usr/bin/env python

import json

sigfile = open("serviceDetections.json", "r")
detectjson = json.load(sigfile)

for detect in detectjson['service detections']:
#  print("-----")
#  print(detect)
  print("-----")
  for signature in detect['signatures']:
    print("Signature: %s" % (signature, ))
  for exception in detect['exceptions']:
    print("Exception: %s" % (exception, ))
  for tag in detect['tags']:
    print("\t-----")
    print("\tName: %s" % (tag['name'], ))
    print("\tType: %s" % (tag['type'], ))
    print("\tSeverity: %s" % (tag['severity'], ))
    print("\tDescription: %s" % (tag['description'], )) 
    for recommendation in tag['recommendations']:
      print("\tRecommendation: %s" % (recommendation, ))

