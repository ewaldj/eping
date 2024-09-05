# eping
eping.py  is a powerful tool that uses python and fping to test the network connectivity of thousands of hosts efficiently and in parallel.


Pings X hosts very quickly (2000 hosts < 4 seconds) thanks to multithreading (-p x) 
Logs every ping (traceability of when a host goes down) in a CSV file
There are several options for what to ping: | Range -r / Network -n / File -f 
It can be used on any machine with Python version > 3.8 and "fping" installed (osx/linux) 
Initial check of which hosts are up, and afterward, only those hosts are pinged. ( -up 3 ) 
Displays the timestamp of the last status change
Displays the number of status changes.
  
