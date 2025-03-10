#!/usr/bin/env python3
##
## OpenLDAP: Report data size in Berkeley DB
##
## SPDX-FileCopyrightText: 2015-2025 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- coding: utf-8 -*- vim:shiftwidth=4:expandtab:

import os
import sys
import re
import subprocess


## Convert Bytes to MiB string
def format_b_as_mib(b, decimal_places=3):
    return '%.*f' % (decimal_places, b / 1024.0 / 1024.0)


def format_sizes(label, size, free, decimal_places=3):
    used = size - free

    return f"""\
{label}: {size} ({format_b_as_mib(size, decimal_places)} MiB)
  Used: {used} ({format_b_as_mib(used, decimal_places)} MiB)
  Free: {free} ({format_b_as_mib(free, decimal_places)} MiB)
"""


DB_STAT_PATH = os.environ.get('DB_SIZE_DB_STAT', '@SBINDIR@/slapd_db_stat')
DB_STATS_PAGE_SIZE_RE = re.compile(r'^(\d+)(M?)\tUnderlying database page size$', re.MULTILINE)
DB_STATS_USED_PAGES_RE = re.compile(r'^(\d+)(M?)\tNumber of tree (\w+) pages$', re.MULTILINE)
DB_STATS_FREE_BYTES_RE = re.compile(r'^(\d+)(M?)\tNumber of bytes free in tree (\w+) pages \(.*\)$', re.MULTILINE)


def db_sizes(db_file):
    out = subprocess.check_output([DB_STAT_PATH, '-d', db_file], encoding='ASCII')
    m = DB_STATS_PAGE_SIZE_RE.search(out)
    page_size = int(m.group(1))

    ## 1 for the root page
    db_pages = 1
    ms = DB_STATS_USED_PAGES_RE.findall(out)
    for m in ms:
        v = int(m[0])
        if m[1]:
            ## 'M' meas MB.
            ## See db-*/src/env/env_stat.c:__db_dl() and __db_dl_pct()
            v *= 1000000
        db_pages += v
    db_size = db_pages * page_size

    db_free = 0
    ms = DB_STATS_FREE_BYTES_RE.findall(out)
    for m in ms:
        v = int(m[0])
        if m[1]:
            ## 'M' meas MB.
            ## See db-*/src/env/env_stat.c:__db_dl() and __db_dl_pct()
            v *= 1000000
        db_free += v

    return db_size, db_free


def main(argv):
    db_size_total = db_free_total = 0
    for db_file in argv:
        db_size, db_free = db_sizes(db_file)
        db_size_total += db_size
        db_free_total += db_free
        print(format_sizes(db_file, db_size, db_free), end='')

    print(format_sizes('Total', db_size_total, db_free_total), end='')

    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: %s *.bdb" % (sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    sys.exit(main(sys.argv[1:]))
