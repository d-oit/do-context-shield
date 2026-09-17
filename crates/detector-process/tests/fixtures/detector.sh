#!/bin/sh
# Test fixture for the process detector protocol: reads one NDJSON request
# from stdin and answers according to the mode in $1.
mode="${1:-ok}"
read -r _request || true
case "$mode" in
  ok)       printf '%s\n' '{"entities":[{"kind":"email","start":0,"end":17,"confidence":0.99}]}' ;;
  two)      printf '%s\n' '{"entities":[{"kind":"phone","start":6,"end":17},{"kind":"email","start":0,"end":5}]}' ;;
  overlap)  printf '%s\n' '{"entities":[{"kind":"person","start":0,"end":5},{"kind":"email","start":0,"end":17}]}' ;;
  mismatch) printf '%s\n' '{"entities":[{"kind":"email","start":0,"end":17,"value":"bob@example.com"}]}' ;;
  badspan)  printf '%s\n' '{"entities":[{"kind":"person","start":1,"end":3}]}' ;;
  junk)     printf '%s\n' 'not json' ;;
  empty)    : ;;
  exit)     exit 3 ;;
  hang)     exec sleep 30 ;;
  *)        printf '%s\n' '{"entities":[]}' ;;
esac
