#!/bin/bash

set -u

export LDIFDIFF_PERL_TEST=1

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

for a_ldif in */entries.a.ldif; do
  b_ldif="${a_ldif%.a.ldif}.b.ldif"
  c_ldif="${a_ldif%.a.ldif}.c.ldif"
  for ldifdiff_cmd in ldifdiff.py ldifdiff.pl; do
    echo "Test: $ldifdiff_cmd ${a_ldif##*/}, ${b_ldif##*/}"
    "$ldifdiff_cmd" \
      "$a_ldif" \
      "$b_ldif" \
    |diff -u "$c_ldif" - \
    ;
  done
done
