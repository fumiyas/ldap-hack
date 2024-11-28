#!/usr/bin/awk -f
##
## LDAP: Unwrap (unfold) lines in LDIF data
##
## SPDX-FileCopyrightText: 2024 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##

NR>1 && !sub(/^ /,"") {
  print s
  s=""
}
{
  s = s $0
}
END {
  print s
}
