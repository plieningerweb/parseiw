Script to parse the output of iw scan command into a table

yh0- 2011-2014 <yysjryysjr DOT gmail DOT com>

Licence: GPLv3

Inspired from iwlist scan parser by Hugo Chargois - 17 jan. 2010, links:
- https://bbs.archlinux.org/viewtopic.php?pid=689963
- https://bbs.archlinux.org/viewtopic.php?pid=737357

Special thanks to jookey!

example 1:
  ./parseiw.py wlan0

example 2:
  ./parseiw.py wlan0 -m #pick a bssid, then run:
  ./parseiw.py <bssid>

example 3: (file)
  iw dev wlan0 scan > output.txt ; ./parseiw.py output.txt -m

example 4: (pipe)
  iw dev wlan0 scan passive | ./parseiw.py

