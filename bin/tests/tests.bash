#!/bin/bash

set -u

cd "${0%/*}" || exit $?

export PATH="..:$PATH"

ldifunwrap.pl() {
  perl -pe 'BEGIN {$/=""} s/\n //gms'
}

for i in awk sed pl; do
  ldifunwrap_cmd="ldifunwrap.$i"
  echo "Test: $ldifunwrap_cmd with valid LDIF data ..."
  for a_ldif in */one-entry-*.ldif; do
    for b_ldif in */one-entry-*.ldif; do
      "$ldifunwrap_cmd" <"$a_ldif" |ldifdiff.py "$b_ldif" /dev/stdin
    done
  done

  echo "Test: $ldifunwrap_cmd with invalid LDIF data ..."
  for a_ldif in data/invalid-*.ldif; do
    # shellcheck disable=SC2094
    # Make sure not to read and write the same file in the same pipeline.
    "$ldifunwrap_cmd" <"$a_ldif" |diff -u "$a_ldif" -
  done
done
