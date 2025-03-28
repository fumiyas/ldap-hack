#!/bin/bash

set -u

cd "${0%/*}" || exit $?

export PATH="..:$PATH"

for ldifunwrap_cmd in ldifunwrap.awk ldifunwrap.sed ldifunwrap.pl; do
  for a_ldif in */one-entry-*.ldif; do
    for b_ldif in */one-entry-*.ldif; do
      for ldifdiff_cmd in ldifdiff.py ldifdiff.pl; do
        echo "Test: $ldifunwrap_cmd: $ldifdiff_cmd: Valid LDIF data: ${a_ldif##*/}, ${b_ldif##*/}"
        "$ldifunwrap_cmd" \
          <"$a_ldif" \
        |"$ldifdiff_cmd" \
          /dev/stdin \
          "$b_ldif" \
        ;
        "$ldifunwrap_cmd" \
          < <(
            cat "$a_ldif"
            echo
            sed 's/^dn:[^,]*/&2/' "$b_ldif"
          ) \
        |"$ldifdiff_cmd" \
          /dev/stdin \
          <(
            sed 's/^dn:[^,]*/&2/' "$b_ldif"
            echo
            cat "$a_ldif"
          ) \
        ;
      done
    done
  done

  for a_ldif in data/invalid-*.ldif; do
    echo "Test: $ldifunwrap_cmd: Invalid LDIF data: ${a_ldif##*/}"
    # shellcheck disable=SC2094 # Make sure not to read and write the same file in the same pipeline
    "$ldifunwrap_cmd" <"$a_ldif" |diff -u "$a_ldif" -
  done
done
