#!/bin/sh
# Test fixture for the process plugin protocol: reads one NDJSON request line
# from stdin and answers according to the mode in $1. The shared error modes
# (`junk`, `empty`, `exit`, `hang`) apply to every capability.
mode="${1:-ok}"
read -r request || true
case "$mode" in
  # detector
  detect-ok)       printf '%s\n' '{"entities":[{"kind":"email","start":0,"end":17,"confidence":0.99}]}' ;;
  detect-two)      printf '%s\n' '{"entities":[{"kind":"phone","start":6,"end":17},{"kind":"email","start":0,"end":5}]}' ;;
  detect-overlap)  printf '%s\n' '{"entities":[{"kind":"person","start":0,"end":5},{"kind":"email","start":0,"end":17}]}' ;;
  detect-mismatch) printf '%s\n' '{"entities":[{"kind":"email","start":0,"end":17,"value":"bob@example.com"}]}' ;;
  detect-badspan)  printf '%s\n' '{"entities":[{"kind":"person","start":1,"end":3}]}' ;;
  # policy
  plan-ok)      printf '%s\n' '{"plan":[{"index":0,"action":"pseudonymize"}]}' ;;
  plan-two)     printf '%s\n' '{"plan":[{"index":0,"action":"pseudonymize"},{"index":1,"action":"redact"}]}' ;;
  plan-missing) printf '%s\n' '{"plan":[{"index":0,"action":"keep"}]}' ;;
  plan-dupe)    printf '%s\n' '{"plan":[{"index":0,"action":"keep"},{"index":0,"action":"redact"}]}' ;;
  plan-range)   printf '%s\n' '{"plan":[{"index":0,"action":"keep"},{"index":7,"action":"keep"}]}' ;;
  plan-unknown) printf '%s\n' '{"plan":[{"index":0,"action":"nope"},{"index":1,"action":"keep"}]}' ;;
  plan-block)   printf '%s\n' '{"plan":[{"index":0,"action":"block"}]}' ;;
  plan-review)  printf '%s\n' '{"plan":[{"index":0,"action":"review"}]}' ;;
  plan-context)
    case "$request" in
      *'"recipient":"unknown"'*) printf '%s\n' '{"plan":[{"index":0,"action":"block"}]}' ;;
      *'"recipient":"local"'*)   printf '%s\n' '{"plan":[{"index":0,"action":"keep"}]}' ;;
      *)                         printf '%s\n' '{"plan":[{"index":0,"action":"redact"}]}' ;;
    esac ;;
  plan-judged)
    case "$request" in
      *'"judgments":[{"index":0,"label":"business","confidence":0.95}]'*) printf '%s\n' '{"plan":[{"index":0,"action":"keep"}]}' ;;
      *) printf '%s\n' '{"plan":[{"index":0,"action":"redact"}]}' ;;
    esac ;;
  # judge
  judge-ok)            printf '%s\n' '{"judgments":[{"index":0,"label":"business","confidence":0.95}]}' ;;
  judge-abstain)       printf '%s\n' '{"judgments":[]}' ;;
  judge-range)         printf '%s\n' '{"judgments":[{"index":7,"label":"personal","confidence":0.9}]}' ;;
  judge-dupe)          printf '%s\n' '{"judgments":[{"index":0,"label":"personal","confidence":0.9},{"index":0,"label":"business","confidence":0.9}]}' ;;
  judge-confidence)    printf '%s\n' '{"judgments":[{"index":0,"label":"personal","confidence":1.5}]}' ;;
  judge-unknown-label) printf '%s\n' '{"judgments":[{"index":0,"label":"banana","confidence":0.9}]}' ;;
  # transformer
  transform-ok)       printf '%s\n' '{"text":"__DO_PRIVATE_EMAIL_1__","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"}]}' ;;
  transform-redact)   printf '%s\n' '{"text":"__DO_PRIVATE_REDACTED__"}' ;;
  transform-leak)     printf '%s\n' '{"text":"alice@example.com __DO_PRIVATE_EMAIL_1__","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"}]}' ;;
  transform-notoken)  printf '%s\n' '{"text":"(removed)","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"}]}' ;;
  transform-unplanned) printf '%s\n' '{"text":"__DO_PRIVATE_PHONE_1__","mappings":[{"kind":"phone","original":"example.com","token":"__DO_PRIVATE_PHONE_1__"}]}' ;;
  transform-foreign)  printf '%s\n' '{"text":"__DO_PRIVATE_EMAIL_9__","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_9__"}]}' ;;
  transform-dropkeep) printf '%s\n' '{"text":"__DO_PRIVATE_REDACTED__"}' ;;
  transform-duplicate-token)   printf '%s\n' '{"text":"__DO_PRIVATE_EMAIL_1__ __DO_PRIVATE_EMAIL_1__","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"},{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"}]}' ;;
  transform-duplicate-mapping) printf '%s\n' '{"text":"__DO_PRIVATE_EMAIL_1__ __DO_PRIVATE_EMAIL_2__","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"},{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_2__"}]}' ;;
  # vault: a hit requires scope s1 and the fixture's one known token
  vault-ok)
    case "$request" in
      *vault_get_or_insert*) printf '%s\n' '{"token":"__DO_PRIVATE_EMAIL_1__"}' ;;
      *'"scope":"s1"'*'"token":"__DO_PRIVATE_EMAIL_1__"'*) printf '%s\n' '{"mapping":{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"}}' ;;
      *) printf '%s\n' '{"mapping":null}' ;;
    esac ;;
  vault-bad-token)   printf '%s\n' '{"token":"NOT_A_PLACEHOLDER"}' ;;
  vault-wrong-token) printf '%s\n' '{"mapping":{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_9__"}}' ;;
  vault-miss)        printf '%s\n' '{"mapping":null}' ;;
  # shared
  junk)  printf '%s\n' 'not json' ;;
  empty) : ;;
  exit)  exit 3 ;;
  hang)  exec sleep 30 ;;
  *)     printf '%s\n' '{"entities":[]}' ;;
esac
