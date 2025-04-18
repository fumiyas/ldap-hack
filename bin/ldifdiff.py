#!/usr/bin/env python3
# -*- coding: utf-8 -*- vim:shiftwidth=4:expandtab:
#
# ldifdiff: Compare two ldif files
#
# SPDX-FileCopyrightText: 2023-2025 SATOH Fumiyasu @ OSSTech Corp., Japan
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Ported from ldif-diff implemented in Perl
# Original ldif-diff copyright:
#   GPL copyright 2004 by VA Linux Systems Japan, K.K
#   Writen by Masato Taruishi <taru@valinux.co.jp>
#
# /// script
# requires-python = ">=3.6"
# dependencies = [
# ]
# ///

## FIXME: Replace debug() with logging module

import sys
import os
import re
import argparse
import base64
import tempfile

debug_p = os.getenv('LDIFDIFF_DEBUG')

kv_re = re.compile(r'^(?P<key>[A-Za-z][-.;0-9A-Za-z]*)::? *(?P<value>.*)')
kv_b64_re = re.compile(r'^(?P<key>[A-Za-z][-.;0-9A-Za-z]*):: *(?P<value>.*)')


def debug(msg):
    if debug_p:
        print(msg, file=sys.stderr)


def entry_read(ldif_in):
    buf = ""
    key = ""
    skipped = False

    for line in ldif_in:
        line = line.rstrip('\r\n')
        if line == '':
            if buf:
                ## End of entry
                break
            ## Skip heading empty lines
            continue
        if line[0] == '#':
            ## Skip comments
            skipped = True
            continue

        if line[0] == ' ':
            if not skipped:
                if not key:
                    raise ValueError(f"Wrapped line without attribute name found: {line}")
                buf += line[1:]
        else:
            colon = line.find(':')
            if colon <= 0:
                raise ValueError(f"Invalid attribute line (no colon `:`): {line}")

            key = line[0:colon]
            if target_attrs:
                if key.lower() != 'dn' and key not in target_attrs:
                    skipped = True
                    continue
            elif (
                key not in include_attrs
                and key in exclude_attrs
            ):
                skipped = True
                continue

            skipped = False
            if buf:
                buf += '\n'
            buf += line

    if not buf:
        return None

    if buf[0:3].lower() != 'dn:':
        raise ValueError(f"No DN line in entry: {buf}")

    lf = buf.find('\n')
    ## FIXME: Support base64-encoded DN value
    dn = buf[4:lf]
    buf = buf[lf + 1:]

    return {
        'dn': dn,
        'entry': buf
    }


def entry_decode(buf):
    dec = []
    for kv in buf.split('\n'):
        m = kv_b64_re.search(kv)
        if m:
            ## FIXME: Support '\n' in decoded value
            dec.append(f"{m.group('key')}: {base64.standard_b64decode(m.group('value'))}")
        else:
            dec.append(kv)

    dec.sort()

    return "\n".join(dec)


def entry2attrs(entry):
    attrs = {}

    if not entry:
        return attrs

    for kv in entry.split('\n'):
        debug(f"entry2attrs: {kv}")
        m = kv_re.search(kv)
        if m:
            key = m.group('key')
            if key in attrs:
                attrs[key] += kv + '\n'
            else:
                attrs[key] = kv + '\n'
        else:
            raise ValueError(f"Invalid line in entry: {kv}")

    return attrs


def modify(oldentry, newentry, oldentry_decode, newentry_decode, dn, modfh):
    debug(f"different: {dn}")
    debug(f"oldentry: {oldentry!r}")
    debug(f"newentry: {newentry!r}")

    print(f"dn: {dn}", file=modfh)
    print("changetype: modify", file=modfh)

    try:
        oldattr = entry2attrs(oldentry)
    except ValueError as e:
        raise ValueError(f"Invalid data in old entry: {dn}") from e

    try:
        oldattr_decode = entry2attrs(oldentry_decode)
    except ValueError as e:
        raise ValueError(f"Invalid data in old decoded entry: {dn}") from e

    try:
        newattr = entry2attrs(newentry)
    except ValueError as e:
        raise ValueError(f"Invalid data in new entry: {dn}") from e

    try:
        newattr_decode = entry2attrs(newentry_decode)
    except ValueError as e:
        raise ValueError(f"Invalid data in new decoded entry: {dn}") from e

    for key in oldattr.keys():
        debug(f"checking attr: {key} for {dn}")

        if key not in newattr:
            debug(f"attr delete: {key}")
            print(f"delete: {key}", file=modfh)
            print("-", file=modfh)
        else:
            if oldattr_decode[key] != newattr_decode[key]:
                debug(f"attr modify: {key} -> {newattr[key].rstrip()}")
                print(f"replace: {key}", file=modfh)
                print(newattr[key], end='', file=modfh)
                print("-", file=modfh)
            del newattr[key]

    for key in newattr.keys():
        debug(f"attr add: {key}")
        print(f"add: {key}", file=modfh)
        print(newattr[key], end='', file=modfh)
        print("-", file=modfh)

    print("", file=modfh)


include_attrs = set()
exclude_attrs = set((
    "modifyTimestamp",
    "modifiersName",
    "contextCSN",
    "entryCSN",
    "entryUUID",
    "createTimestamp",
    "creatorsName",
    "structuralObjectClass",
    "entryDN",
    "subschemaSubentry",
    "numSubordinates",
    "hasSubordinates",
))

args_parser = argparse.ArgumentParser(
    prog=sys.argv[0],
    add_help=True,
)
args_parser.add_argument(
    'file1', metavar='FILE1',
    help='LDIF file 1',
)
args_parser.add_argument(
    'file2', metavar='FILE2',
    help='LDIF file 2',
)
args_parser.add_argument(
    'target_attrs', metavar='ATTRIBUTE',
    nargs='*',
    help='Attribute name(s) to compare',
)
## FIXME: Support multiple -i option
args_parser.add_argument(
    '--include-attrs', '-i', metavar='NAME',
    ## FIXME: Describe comma-separated value
    help='Specify attribute name(s) to be included'
)
## FIXME: Support multiple -e option
args_parser.add_argument(
    '--exclude-attrs', '-e', metavar='NAME',
    ## FIXME: Describe comma-separated value
    help='Specify attribute name(s) to be excluded'
)
args = args_parser.parse_args()

if args.include_attrs:
    include_attrs.update(args.include_attrs.split(','))
if args.exclude_attrs:
    exclude_attrs.update(args.exclude_attrs.split(','))

target_attrs = args.target_attrs

oldin = open(args.file1)
newin = open(args.file2)
modfh = tempfile.TemporaryFile('w+')

oldentry = {}
oldentry_decode = {}
newentry = {}
newentry_decode = {}

while True:
    odn = ""
    ndn = ""

    oe = entry_read(oldin)
    if oe:
        odn = oe['dn']
        oldentry[odn] = oe['entry']

    ne = entry_read(newin)
    if ne:
        ndn = ne['dn']
        newentry[ndn] = ne['entry']

    if not oe and not ne:
        break

    if odn in newentry and odn in oldentry:
        debug(f'checking {odn}')
        if odn not in oldentry_decode:
            oldentry_decode[odn] = entry_decode(oldentry[odn])
        if odn not in newentry_decode:
            newentry_decode[odn] = entry_decode(newentry[odn])

        if newentry_decode[odn] != oldentry_decode[odn]:
            modify(oldentry[odn], newentry[odn], oldentry_decode[odn], newentry_decode[odn], odn, modfh)
        else:
            debug(f'same: {odn}')

        del oldentry[odn]
        del oldentry_decode[odn]
        del newentry[odn]
        del newentry_decode[odn]

    if ndn in newentry and ndn in oldentry:
        debug(f'checking {ndn}')
        if ndn not in oldentry_decode:
            oldentry_decode[ndn] = entry_decode(oldentry[ndn])
        if ndn not in newentry_decode:
            newentry_decode[ndn] = entry_decode(newentry[ndn])

        if newentry_decode[ndn] != oldentry_decode[ndn]:
            modify(oldentry[ndn], newentry[ndn], oldentry_decode[ndn], newentry_decode[ndn], ndn, modfh)
        else:
            debug(f'same: {ndn}')

        del oldentry[ndn]
        del oldentry_decode[ndn]
        del newentry[ndn]
        del newentry_decode[ndn]

for dn in sorted(oldentry.keys(), key=len, reverse=True):
    debug(f"delete: {dn}")
    print(f"dn: {dn}")
    print("changetype: delete")
    print("")

for dn in sorted(newentry.keys(), key=len):
    debug(f"add: {dn}")
    print(f"dn: {dn}")
    print("changetype: add")
    print(newentry[dn])
    print("")

modfh.seek(0)
for line in modfh:
    print(line, end='')
