#!/bin/sh
# Naprzemiennie: nginx działa FLAP_UP s, potem jest zatrzymany FLAP_DOWN s.
UP=${FLAP_UP:-300}; DOWN=${FLAP_DOWN:-300}
while true; do
  nginx
  echo "flapper: UP for ${UP}s"
  sleep "$UP"
  nginx -s stop
  echo "flapper: DOWN for ${DOWN}s"
  sleep "$DOWN"
done
