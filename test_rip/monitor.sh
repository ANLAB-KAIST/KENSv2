#!/bin/sh
if [ -z "$1" ]; then
    echo Usage: $0 LOG_FILE [FILTER_PATTERN]
    exit 1
fi

LOGFILE="$1"

shift

if [ -z "$*" ]; then
    tail -s 0.1 -F "$LOGFILE"
else
    tail -s 0.1 -F "$LOGFILE" | grep "$*"
fi
