# !/bin/bash

if [ -e gwtest.pid ]; then
    kill `cat gwtest.pid` >& /dev/null
    sleep 1
fi

KENS=../src/kens

truncate -s0 *.log

$KENS gw1.conf &
PIDS=$!
$KENS gw2.conf &
PIDS="$PIDS $!"
$KENS svr.conf &
PIDS="$PIDS $!"
$KENS cli.conf &
PIDS="$PIDS $!"

cat > gwtest.pid << _EOF
$PIDS
_EOF
