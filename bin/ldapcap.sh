#!/bin/bash
##
## Query LDAP server capabilities
## Copyright (c) 2007-2023 SATOH Fumiyasu @ OSSTech Corp, Japan
##               <https://www.OSSTech.co.jp/>
##               <https://GitHub.com/fumiyas/>
##
## License: GNU General Public License version 2 or later
##

## LDAP, Lightweight Directory Access Protocol
## http://www.networksorcery.com/enp/protocol/ldap.htm
## LDAP OID Reference Guide – LDAP.com
## https://ldap.com/ldap-oid-reference-guide/
## Directory Services 7 > LDAP Reference > Supported LDAP Controls
## https://backstage.forgerock.com/docs/ds/7/ldap-reference/controls.html
## Directory Services 7 > LDAP Reference > Supported LDAP Extended Operations
## https://backstage.forgerock.com/docs/ds/7/ldap-reference/extended-ops.html
set -u
set -e

if [ $# -eq 0 ]; then
  echo "Usage: $0 ldap[s]://SERVER[:PORT]"
  exit 0
fi

url="$1"; shift

ldapsearch \
  -LLL \
  -x \
  -H "$url" \
  -b '' \
  -s base \
  'objectclass=*' \
  '*' \
  '+' \
|while read -r attr value; do
  desc=""

  case "$attr" in
  supported*:)
    desc="Unknown: $attr $value"
    case "$value" in
    1.2.826.0.1.3344810.2.3)
      desc="Matched Values Control (RFC 3876)"
      ;;
    1.2.840.113556.1.4.319)
      desc="Paged search Control (RFC 2696)"
      ;;
    1.2.840.113556.1.4.417)
      desc="Show deleted Control"
      ;;
    1.2.840.113556.1.4.473)
      desc="Sort Request (RFC 2891)"
      ;;
    1.2.840.113556.1.4.474)
      desc="Sort Response (RFC 2891)"
      ;;
    1.2.840.113556.1.4.521)
      desc="Cross-domain move Control"
      ;;
    1.2.840.113556.1.4.528)
      desc="Server search notification Control"
      ;;
    1.2.840.113556.1.4.529)
      desc="Extended DN Control"
      ;;
    1.2.840.113556.1.4.619)
      desc="Lazy commit Control"
      ;;
    1.2.840.113556.1.4.801)
      desc="Security descriptor flags Control"
      ;;
    1.2.840.113556.1.4.802)
      desc="Server range option"
      ;;
    1.2.840.113556.1.4.805)
      desc="Tree delete Control"
      ;;
    1.2.840.113556.1.4.841)
      desc="Directory synchronization Control"
      ;;
    1.2.840.113556.1.4.970)
      desc="Get stats Control"
      ;;
    1.2.840.113556.1.4.1338)
      desc="Verify name Control"
      ;;
    1.2.840.113556.1.4.1339)
      desc="Domain scope Control"
      ;;
    1.2.840.113556.1.4.1340)
      desc="Search options Control"
      ;;
    1.2.840.113556.1.4.1341)
      desc="SERVER_RODC_DCPROMO"
      ;;
    1.2.840.113556.1.4.1413)
      desc="Permissive modify Control"
      ;;
    1.2.840.113556.1.4.1504)
      desc="Attribute scoped query Control"
      ;;
    1.2.840.113556.1.4.1781)
      desc="Fast concurrent bind extended operation"
      ;;
    1.2.840.113556.1.4.1852)
      desc="Server Quota Control"
      ;;
    1.2.840.113556.1.4.1907)
      desc="Server Shutdown Notify"
      ;;
    1.2.840.113556.1.4.1948)
      desc="Server Range Retrieval No-error"
      ;;
    1.2.840.113556.1.4.1974)
      desc="Server Force Update"
      ;;
    1.2.840.113556.1.4.2026)
      desc="Server Input DN"
      ;;
    1.3.6.1.1.8)
      desc="Cancel Operation (RFC 3909)"
      ;;
    1.3.6.1.1.12)
      desc="Assertion Control (RFC 4528)"
      ;;
    1.3.6.1.1.13.1)
      desc="LDAP Pre-read Control (RFC 4527)"
      ;;
    1.3.6.1.1.13.2)
      desc="LDAP Post-read Control (RFC 4527)"
      ;;
    1.3.6.1.1.14)
      desc="Modify-Increment Feature (RFC 4525)"
      ;;
    1.3.6.1.4.1.42.2.27.9.5.8)
      desc="Account Usable Request and Response Control (Sun)"
      ;;
    1.3.6.1.4.1.1466.101.119.1)
      desc="Dynamic Refresh (RFC 2589)"
      ;;
    1.3.6.1.4.1.1466.20037)
      desc="Start TLS (RFC 2830, RFC 4511, RFC 4513)"
      ;;
    1.3.6.1.4.1.4203.1.5.1)
      desc="All Operational Attributes Feature (RFC 3673)"
      ;;
    1.3.6.1.4.1.4203.1.5.2)
      desc="OC AD Lists (RFC 4529)"
      ;;
    1.3.6.1.4.1.4203.1.5.3)
      desc="True/False filters (RFC 4526)"
      ;;
    1.3.6.1.4.1.4203.1.5.4)
      desc="Language Tag Options (RFC 3866)"
      ;;
    1.3.6.1.4.1.4203.1.5.5)
      desc="Language Range Options (RFC 3866)"
      ;;
    1.3.6.1.4.1.4203.1.9.1.1)
      desc="LDAP Content Synchronization Control (RFC 4533)"
      ;;
    1.3.6.1.4.1.4203.1.10.1)
      desc="Subentries (RFC 3672)"
      ;;
    1.3.6.1.4.1.4203.1.11.1)
      desc="Modify Password (RFC 3062)"
      ;;
    1.3.6.1.4.1.4203.1.11.3)
      desc="Who am I? (RFC 4532)"
      ;;
    2.16.840.1.113730.3.4.2)
      desc="Manage DSA IT Control (RFC 3296)"
      ;;
    2.16.840.1.113730.3.4.4)
      desc="Password Expired LDAPv3 Control (Netscape)"
      ;;
    2.16.840.1.113730.3.4.5)
      desc="Password Expiring LDAPv3 Control (Netscape)"
      ;;
    2.16.840.1.113730.3.4.9)
      desc="Virtual List View (VLV) Request"
      ;;
    2.16.840.1.113730.3.4.10)
      desc="Virtual List View (VLV) Response"
      ;;
    2.16.840.1.113730.3.4.18)
      desc="Proxy Authorization Control (RFC 4370)"
      ;;
    esac
    ;;
  esac

  if [[ -n $desc ]]; then
    echo "## $desc"
  fi
  echo "$attr $value"
done
