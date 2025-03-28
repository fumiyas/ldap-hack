#!/bin/bash
##
## OpenLDAP: certbot(1) --deploy-hook script for the server certificate
##
## SPDX-FileCopyrightText: 2023-2025 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##

set -u
set -o pipefail || exit $?		## bash 3.0+
shopt -s lastpipe || exit $?		## bash 4.2+

set -e

run() {
  if [[ -n ${SLAPDRENEWCERT_DEBUG-} ]]; then
    echo "$0: DEBUG: Run: $*" 1>&2
  fi
  if [[ -n ${SLAPDRENEWCERT_NO_RUN-} ]]; then
    return
  fi
  "$@"
}

run_or_discard_stdin() {
  if [[ -n ${SLAPDRENEWCERT_DEBUG-} ]]; then
    echo "$0: DEBUG: Run: $*" 1>&2
  fi
  if [[ -n ${SLAPDRENEWCERT_NO_RUN-} ]]; then
    sed d
  fi
  "$@"
}

run_always() {
  if [[ -n ${SLAPDRENEWCERT_DEBUG-} ]]; then
    echo "$0: DEBUG: Run: $*" 1>&2
  fi
  "$@"
}

## Generate install(1) options from a path to preserve the mode, owner and group
path2install_options() {
  local path="$1"; shift
  local mode owner group

  if [[ -s $path ]]; then
    # shellcheck disable=SC2012 # Use find instead of ls ...
    ls -dln -- "$path" \
    |sed -n -E '1s/^.(...)(...)(...) +[0-9]+/u=\1,g=\2,o=\3/p' \
    |read -r mode owner group _ \
    ;
  else
    mode='0440'
    for group_try in ldap openldap; do
      if getent group "$group_try" >/dev/null; then
        group="$group_try"
        break
      fi
    done
  fi

  echo "${mode+-m $mode} ${owner+-o $owner} ${group+-g $group}"
}

install_command_options=(--backup)
ldap_command_options=(-H ldapi:/// -Y external -Q)
cb_cert_path="$RENEWED_LINEAGE/fullchain.pem"
cb_key_path="$RENEWED_LINEAGE/privkey.pem"

pubkey_digest1=$(openssl x509 -pubkey -in "$cb_cert_path" -noout |openssl md5)
pubkey_digest2=$(openssl pkey -pubout -in "$cb_key_path" |openssl md5)
if [[ "$pubkey_digest1" != "$pubkey_digest2" ]]; then
  echo "$0: ERROR: Invalid certificate/key pair" 1>&2
  exit 1
fi

## FIXME: If slapd is not running? (or no slapi:/// socket)
## FIXME: Support olcTLSCertificate, olcTLSCertificateKey (binary in DIT)
## FIXME: Support oldBkLloadTLS...

run_always ldapsearch \
  "${ldap_command_options[@]}" \
  -b cn=config \
  -s base \
  -LLL \
  -o ldif-wrap=no \
  '(objectClass=*)' \
  olcTLSCertificateFile \
  olcTLSCertificateKeyFile \
|tee ${SLAPDRENEWCERT_DEBUG+>(sed -n "s|^.|$0: DEBUG: Current cn=config: &|p" >/dev/stderr)} \
|while IFS=' ' read -r attr value; do
  case "$attr" in
  olcTLSCertificateFile:)
    cert_path="$value"
    ;;
  olcTLSCertificateKeyFile:)
    key_path="$value"
    ;;
  esac
done

# shellcheck disable=SC2046 # Quote this to prevent word splitting
run install \
  "${install_command_options[@]}" \
  $(path2install_options "$cert_path") \
  "$cb_cert_path" \
  "$cert_path" \
;
# shellcheck disable=SC2046 # Quote this to prevent word splitting
run install \
  "${install_command_options[@]}" \
  $(path2install_options "$key_path") \
  "$cb_key_path" \
  "$key_path" \
;

{
echo "\
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: $cert_path
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $key_path
-
"
} \
|tee ${SLAPDRENEWCERT_DEBUG+>(sed -n "s|^.|$0: DEBUG: Renew cn=config: &|p" >/dev/stderr)} \
|run_or_discard_stdin ldapmodify \
  "${ldap_command_options[@]}" \
>/dev/null \
;

exit 0
