#!/bin/sh

if [ -e gwtest.pid ]; then
    kill `cat gwtest.pid` >& /dev/null
    sleep 1
fi

KENS=../src/kens

rm -f *.log

$KENS gw0.conf &
PIDS=$!
$KENS gw1.conf &
PIDS="$PIDS $!"
$KENS gwa.conf &
PIDS="$PIDS $!"
$KENS gwb.conf &
PIDS="$PIDS $!"
$KENS svr.conf &
PIDS="$PIDS $!"
$KENS cli.conf &
PIDS="$PIDS $!"

cat > gwtest.pid << _EOF
$PIDS
_EOF
