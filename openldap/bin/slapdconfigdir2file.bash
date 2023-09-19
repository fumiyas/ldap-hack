#!/bin/bash
##
## OpenLDAP: Convert slapd.d to slapd.conf
## Copyright (c) 2023 SATOH Fumiyasu @ OSSTech Corp., Japan
##
## License: GNU General Public License version 3

## FIXME: Support for slapd.conf(5) directive names in the "Foo-Bar-Qux" or
##        "Foo_Bar_Qux" format, rather than the "FooBarQux" format.
## FIXME: Test with `{10}...` ... lines in slapd.d/**.ldif
## FIXME: Support slapd.d/olcDatabase={10}*.ldif ... files in slapd.d
## FIXME: Support slapd.d/olcDatabase=*/olcOverlay={10}*.ldif ... files in slapd.d

set -u

## ======================================================================

pwarn() {
  echo "$0: WARNING: $1" 1>&2
}

# shellcheck disable=SC2016
ldif_unbase64_perl='
## Decode base64-encoded attribute values in LDIF data
## Copyright (c) 2013-2019 SATOH Fumiyasu @ OSS Technology Corp., Japan

use strict;
use warnings;
use Encode;
use MIME::Base64;

sub unbase64
{
  my ($name, $value_b64) = @_;

  my $value = MIME::Base64::decode($value_b64);
  my $value_utf8 = eval {
    Encode::decode_utf8(my $value_tmp=$value, Encode::FB_CROAK);
  };

  unless (!$@ && $value_utf8 =~ /\A[\p{IsPrint}\t\n\r\e]*\z/) {
    return "${name}::$value_b64";
  }

  return "$name: $value\n";
}

$/ = "\n\n";
while (<>) {
  s/^(\w[\w\-]*(?:;\w[\w\-]*)*)::((?:[ \t]*[^\n]*\n)(?:[ \t]+[^\n]*\n)*)/unbase64($1, $2)/mge;
  print;
}
'

ldif_unbase64() {
  if type perl >/dev/null 2>&1; then
    perl -e "$ldif_unbase64_perl"
  else
    pwarn "perl not found to decode Base64 values in *.ldif"
    cat
  fi
}

ldif_unwrap() {
  sed \
    -n \
    -e '1{ h; $!d; }' \
    -e '${ x; s/\n //g; p; }' \
    -e '/^ /{ H; d; }' \
    -e '/^ /!{ x; s/\n //g; p; }' \
    "$@" \
  ;
}

ldif_normalize() {
  ldif_unwrap "$@" |ldif_unbase64
}

## ======================================================================

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 SLAPD_DIR"
  exit 1
fi
slapd_dir="$1"; shift

cd "$slapd_dir" || exit $?

for schema_ldif_file in cn=config/cn=schema/cn=*.ldif; do
  [[ -f $schema_ldif_file ]] || continue

  schema_ldif_basename="${schema_ldif_file##*/}"
  schema_basename="${schema_ldif_basename#cn=\{*\}}"
  schema_name="${schema_basename%.ldif}"

  echo "## Schema: ${schema_name}"
  echo "## ======================================================================"

  ldif_normalize "$schema_ldif_file" \
  |sed -E -n \
    -e 's/^olc([A-Z][A-Za-z]+): \{[0-9]+\}/\1 /p' \
  |sed -E \
    -e 's/^AttributeTypes /AttributeType /' \
    -e 's/^ObjectClasses /ObjectClass /' \
    -e 's/ +(NAME|DESC|SYNTAX|SUP|EQUALITY|SUBSTR)([ \)])/\n\t\1\2/g' \
    -e 's/ +(SINGLE-VALUE)([ \)])/\n\t\1\2/g' \
    -e 's/ +(STRUCTURAL|AUXILIARY)([ \)])/\n\t\1\2/g' \
    -e 's/ +(MUST|MAY)([ \)])/\n\t\1\2/g' \
  ;
  echo
done

ldif_normalize cn=config/cn=module*.ldif \
|sed -E -n \
  -e 's/^olc(ModuleLoad): \{[0-9]+\}([^.]+)(\.[a-z]+)?$/\1 \2/p' \
;
echo

ldif_normalize cn=config.ldif \
|sed -E -n \
  -e 's/^olc([A-Z][A-Za-z]+): /\1 /p' \
;
echo

db_n=-1
for db_ldif_file in cn=config/olcDatabase=*.ldif; do
  [[ -f $db_ldif_file ]] || continue

  db_ldif_basename="${db_ldif_file##*/}"
  db_basename="${db_ldif_basename#olcDatabase=\{*\}}"
  db_type="${db_basename%.ldif}"
  db_config_dir="cn=config/${db_ldif_basename%.ldif}"

  if [[ $db_type == 'frontend' ]]; then
      echo "## Frontend"
  else
    ((db_n++))
    if [[ $db_type == @(*db|wt) ]]; then
      db_suffix="FIXME"
    else
      db_suffix="cn=$db_type"
    fi
    echo "## Database #$db_n: cn=$db_suffix"
  fi

  echo "## ======================================================================"
  echo
  echo "Database $db_type"

  ldif_normalize "$db_ldif_file" \
  |sed -E -n \
    -e '/^olcDatabase:/d' \
    -e 's/^olc(Db)?([A-Z][A-Za-z]+): (\{[0-9]+\})?/\2 /p' \
  |sed -E \
    -e 's/^(Root(DN|PW) )(.*)$/\1"\3"/' \
    -e '/^(Access )/s/ by /\n\tby /g' \
  ;

  for db_overlay_ldif_file in "$db_config_dir"/olcOverlay=*.ldif; do
    [[ -f $db_overlay_ldif_file ]] || continue

    db_overlay_ldif_basename="${db_overlay_ldif_file##*/}"
    db_overlay_basename="${db_overlay_ldif_basename#olcOverlay=\{*\}}"
    db_overlay_name="${db_overlay_basename%.ldif}"

    #echo
    #echo "## Overlay: $db_overlay_name"
    #echo "----------------------------------------------------------------------"
    echo
    echo "Overlay $db_overlay_name"

    ldif_normalize "$db_overlay_ldif_file" \
    |sed -E -n \
      -e '/^olcOverlay:/d' \
      -e 's/^olc([A-Z][A-Za-z]+): (\{[0-9]+\})?/\1 /p' \
    ;
  done

  echo
done
