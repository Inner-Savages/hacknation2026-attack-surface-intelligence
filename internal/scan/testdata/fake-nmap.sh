#!/bin/sh
# Stands in for nmap in tests: reads targets from stdin (-iL -) and reports
# each as up with 80/tcp (or $FAKE_NMAP_PORT) open. A target named fail.test makes it exit 1.
# FAKE_NMAP_US: microseconds to take per target. FAKE_NMAP_LOG: file to append scanned targets to
# (after the delay, so cancelled runs do not count). FAKE_NMAP_VAGUE: the service stays
# unidentified when a tuned probe database is used.
targets=$(cat)
if [ -n "$FAKE_NMAP_US" ]; then
  n=$(printf '%s\n' "$targets" | wc -l)
  delay=$(awk -v n="$n" -v us="$FAKE_NMAP_US" 'BEGIN{printf "%.4f", n*us/1e6}')
  sleep "$delay" &
  trap 'kill $!; exit 143' TERM
  wait $!
fi
case "$targets" in *fail.test*) echo "fake nmap: failure requested" >&2; exit 1 ;; esac
[ -n "$FAKE_NMAP_LOG" ] && printf '%s\n' "$targets" >> "$FAKE_NMAP_LOG"
service='<service name="http" product="nginx" method="probed" conf="10"/>'
if [ -n "$FAKE_NMAP_VAGUE" ]; then
  case "$*" in *--versiondb*) service='<service name="ppp" method="table" conf="3"/>' ;; esac
fi
echo '<?xml version="1.0"?><nmaprun>'
for t in $targets; do
  echo "<host><status state=\"up\" reason=\"syn-ack\"/><address addr=\"$t\" addrtype=\"ipv4\"/><ports>"
  echo "<port protocol=\"tcp\" portid=\"${FAKE_NMAP_PORT:-80}\"><state state=\"open\" reason=\"syn-ack\"/>$service</port>"
  echo "</ports></host>"
done
echo '</nmaprun>'
