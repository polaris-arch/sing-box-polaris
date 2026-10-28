#!/usr/bin/env python3
"""One branded version spelling for native artifact names and release metadata."""
import os,re,sys
PATTERN=r'[0-9]+\.[0-9]+\.[0-9]+-polaris-(?:alpha|beta|rc)\.(?:0|[1-9][0-9]*)'
def validate(value):
 if not re.fullmatch(PATTERN,value):raise ValueError('expected MAJOR.MINOR.PATCH-polaris-{alpha,beta,rc}.NUMBER')
 return value
if __name__=='__main__':
 value=validate(sys.argv[1] if len(sys.argv)>1 else os.environ['CANDIDATE_VERSION'])
 if len(sys.argv)>2:
  number=sys.argv[2]
  if not number.isdecimal() or not 0<int(number)<=65535:raise ValueError('CI build number exceeds Windows numeric resource range')
  if any(int(x)>65535 for x in value.split('-')[0].split('.')):raise ValueError('Windows numeric version component exceeds 65535')
 print(value)
