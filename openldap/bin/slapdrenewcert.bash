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

install_command_options=(--backup)
ldap_command_options=(-H ldapi:/// -Y external -Q)
ldap_group="openldap"
cb_cert_path="$RENEWED_LINEAGE/fullchain.pem"
cb_key_path="$RENEWED_LINEAGE/privkey.pem"

pubkey_digest1=$(openssl x509 -pubkey -in "$cb_cert_path" -noout |openssl md5)
pubkey_digest2=$(openssl pkey -pubout -in "$cb_key_path" |openssl md5)
if [[ "$pubkey_digest1" != "$pubkey_digest2" ]]; then
  echo "$0: ERROR: Invalid certificate/key pair" 1>&2
  exit 1
fi

ldapsearch \
  "${ldap_command_options[@]}" \
  -b cn=config \
  -s base \
  -LLL \
  -o ldif-wrap=no \
  '(objectClass=*)' \
  olcTLSCertificateFile \
  olcTLSCertificateKeyFile \
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

install \
  "${install_command_options[@]}" \
  -m 0444 \
  -g "$ldap_group" \
  "$cb_cert_path" \
  "$cert_path" \
;
install \
  "${install_command_options[@]}" \
  -m 0440 \
  -g "$ldap_group" \
  "$cb_key_path" \
  "$key_path" \
;

(
  echo 'dn: cn=config'
  echo 'changetype: modify'
  echo 'replace: olcTLSCertificateFile'
  echo "olcTLSCertificateFile: $cert_path"
  echo -
  echo 'replace: olcTLSCertificateKeyFile'
  echo "olcTLSCertificateKeyFile: $key_path"
  echo -
) \
|ldapmodify \
  "${ldap_command_options[@]}" \
>/dev/null \
;

exit 0
