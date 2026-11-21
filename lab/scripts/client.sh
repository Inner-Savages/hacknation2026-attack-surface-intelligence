#!/bin/sh
# Ruch w tle: co kilka sekund odpytuje usługi labu (wget z busyboxa).
HOSTS="172.28.0.10 172.28.0.11 172.28.0.12 172.28.0.20"
while true; do
  for h in $HOSTS; do
    wget -q -O /dev/null -T 2 "http://$h/" 2>/dev/null
  done
  wget -q -O /dev/null -T 2 "http://172.28.0.11/wp-login.php" 2>/dev/null
  wget -q -O /dev/null -T 2 "http://172.28.0.12/admin/" 2>/dev/null
  sleep 5
done
