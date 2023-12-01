#!/usr/bin/env python3
## -*- coding: utf-8 -*- vim:shiftwidth=4:expandtab:
##
## ldifdiff: Compare two ldif files
## Copyright (c) 2023 SATOH Fumiyasu @ OSSTech Corp., Japan
##
## Ported from ldif-diff implemented in Perl
##
## Original ldif-diff copyright:
##   GPL copyright 2004 by VA Linux Systems Japan, K.K
##   Writen by Masato Taruishi <taru@valinux.co.jp>
##

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


def entry(ldif_in):
    buf = ""
    dn = None
    key = ""
    skipped = False

    for line in ldif_in:
        line = line.rstrip('\n')
        if line == '':
            if buf:
                break
            continue
        if line[0] == '#':
            skipped = True
            continue

        if line[0] == ' ':
            if not skipped:
                if not key:
                    raise ValueError(f"Wrapped line without attribute name found: {line}")
                buf = buf + line[1:]
        else:
            colon = line.find(':')
            if colon <= 0:
                raise ValueError(f"Invalid attribute line (no colon `:`): {line}")

            if dn is None and buf:
                if buf[0:3] != 'dn:':
                    raise ValueError(f"Invalid DN line: {buf}")
                dn = buf[3:].lstrip(' ')
                buf = ""

            key = line[0:colon]
            if key in include_attrs or key not in exclude_attrs:
                skipped = False
                if buf:
                    buf += '\n'
                buf += line
            else:
                skipped = True

    if dn is None:
        return None

    return {
        'dn': dn,
        'entry': buf
    }


def decode(buf):
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


def modify(oldentry, newentry, oldentry_decode, newentry_decode, dn, modfh):
    debug(f"different: {dn}")

    oldattr = {}
    oldattr_decode = {}
    newattr = {}
    newattr_decode = {}

    print(f"dn: {dn}", file=modfh)
    print("changetype: modify", file=modfh)

    for kv in oldentry.split('\n'):
        debug(f"adding old attr: {kv} for {dn}")
        m = kv_re.search(kv)
        if m:
            key = m.group('key')
            if key not in oldattr:
                oldattr[key] = ''
            oldattr[key] += kv + '\n'
        else:
            raise ValueError(f"Unsupported LDIF format: {kv}")

    for kv in oldentry_decode.split('\n'):
        m = kv_re.search(kv)
        if m:
            key = m.group('key')
            if key not in oldattr_decode:
                oldattr_decode[key] = ''
            oldattr_decode[key] += kv + '\n'
        else:
            raise ValueError(f"Unsupported LDIF format: {kv}")

    for kv in newentry.split('\n'):
        debug(f"adding new attr: {kv} for {dn}")
        m = kv_re.search(kv)
        if m:
            key = m.group('key')
            if key not in newattr:
                newattr[key] = ''
            newattr[key] += kv + '\n'
        else:
            raise ValueError(f"Unsupported LDIF format: {kv}")

    for kv in newentry_decode.split('\n'):
        m = kv_re.search(kv)
        if m:
            key = m.group('key')
            if key not in newattr_decode:
                newattr_decode[key] = ''
            newattr_decode[key] += kv + '\n'
        else:
            raise ValueError(f"Unsupported LDIF format: {kv}")

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


exclude_attrs = set((
    "modifyTimestamp",
    "modifiersName",
    "contextCSN",
    "entryCSN",
    "entryUUID",
    "createTimestamp",
    "creatorsName",
    "structuralObjectClass",
    "numSubordinates",
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
    ## FIXME '--include-attrs', '-i', metavar='NAME',
    '--exclude-attrs', '-e', metavar='NAME',
    help='Specify attribute name(s) to be excluded'
)
args = args_parser.parse_args()

if args.exclude_attrs:
    exclude_attrs.update(args.exclude_attrs.split(','))

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

    oe = entry(oldin)
    if oe:
        odn = oe['dn']
        oldentry[odn] = oe['entry']

    ne = entry(newin)
    if ne:
        ndn = ne['dn']
        newentry[ndn] = ne['entry']

    if not oe and not ne:
        break

    if odn in newentry and odn in oldentry:
        debug(f'checking {odn}')
        if odn not in oldentry_decode:
            oldentry_decode[odn] = decode(oldentry[odn])
        if odn not in newentry_decode:
            newentry_decode[odn] = decode(newentry[odn])

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
            oldentry_decode[ndn] = decode(oldentry[ndn])
        if ndn not in newentry_decode:
            newentry_decode[ndn] = decode(newentry[ndn])

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
