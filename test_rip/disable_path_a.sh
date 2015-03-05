#!/bin/sh
. gwa.sh
../src/kensctrl set disable_seth 1
. gwb.sh
../src/kensctrl set enable_seth 1
