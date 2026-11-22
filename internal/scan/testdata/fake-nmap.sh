#!/bin/sh
# Stands in for nmap in tests: reads targets from stdin (-iL -) and reports
# each as up with 80/tcp (or $FAKE_NMAP_PORT) open. A target named fail.test makes it exit 1.
targets=$(cat)
case "$targets" in *fail.test*) echo "fake nmap: failure requested" >&2; exit 1 ;; esac
echo '<?xml version="1.0"?><nmaprun>'
for t in $targets; do
  echo "<host><status state=\"up\" reason=\"syn-ack\"/><address addr=\"$t\" addrtype=\"ipv4\"/><ports>"
  echo "<port protocol=\"tcp\" portid=\"${FAKE_NMAP_PORT:-80}\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"http\" product=\"nginx\"/></port>"
  echo "</ports></host>"
done
echo '</nmaprun>'
