#!/usr/bin/sed -nf
##
## LDAP: Unwrap (unfold) lines in LDIF data
##
## SPDX-FileCopyrightText: 2024 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##

/^ /! {
  1! {
    x
    s/\n //g
    p
    x
  }
  $ {
    p
    q
  }
  h
  d
}

/^ / {
  H
}

$ {
  x
  s/\n //g
  p
}
