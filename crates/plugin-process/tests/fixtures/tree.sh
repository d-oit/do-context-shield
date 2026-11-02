#!/bin/sh
# Process-tree fixture: read one request, start a grandchild that inherits
# stdout (so a reader blocks on the pipe), record its pid for the test, and
# hang. A timeout must terminate both processes, not just the direct child.
read -r _request || true
pid_file="${1:-}"
if [ -n "$pid_file" ]; then
  sh -c 'exec sleep 300' &
  printf '%s\n' "$!" > "$pid_file"
else
  sh -c 'exec sleep 300' &
fi
wait
