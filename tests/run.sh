#!/bin/sh
# Run the test scripts. --offline runs only the ones that start their own local servers.
# Uses the repo's .venv Python if there is one; set PYTHON to use another.
cd "$(dirname "$0")" || exit 1
PY="${PYTHON:-../.venv/bin/python}"
[ -x "$PY" ] || PY=python3

if [ "$1" = "--offline" ]; then
    tests="forms_test.py audit_test.py security_test.py tunnel_test.py"
else
    tests=$(ls *_test.py)
fi

log=$(mktemp)
failed=0
for t in $tests; do
    if "$PY" "$t" >"$log" 2>&1; then
        echo "pass  $t"
    else
        echo "FAIL  $t"
        grep -v '^\[pid' "$log" | tail -n 15 | sed 's/^/      /'
        failed=$((failed + 1))
    fi
done
rm -f "$log"
[ "$failed" -eq 0 ] && echo "all passed" || { echo "$failed failed"; exit 1; }
