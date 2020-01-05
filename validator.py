# -*- coding: utf-8 -*-

"""
"""

import json

sigfile = open("serviceDetections.json", "r")
detectjson = json.load(sigfile)
sigfile.close()

def main():
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


if __name__== "__main__":
  main()

__author__     = ''
__copyright__  = ''
__credits__    = ['{credit_list}']
__license__    = '{license}'
__version__    = ''
__maintainer__ = ''
__email__      = ''
