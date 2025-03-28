#!/bin/bash

set -u

cd "${0%/*}" || exit $?

export PATH="..:$PATH"

for a_ldif in */one-entry-*.ldif; do
  for b_ldif in */one-entry-*.ldif; do
    for ldifdiff_cmd in ldifdiff.py ldifdiff.pl; do
      echo "Test: $ldifdiff_cmd ${a_ldif##*/}, ${b_ldif##*/}"
      "$ldifdiff_cmd" \
        "$a_ldif" \
        "$b_ldif" \
      ;
    done
  done
done
