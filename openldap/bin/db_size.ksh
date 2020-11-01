#!/bin/ksh
##
## OpenLDAP: Report data size in Berkeley DB
## Copyright (c) 2015-2020 SATOH Fumiyasu @ OSS Technology Corp., Japan
##               <https://www.osstech.co.jp/>
##               <https://github.com/fumiyas/>
##
## License: GNU General Public License version 2 or later
##

set -u

## Bytes -> MiB
function b_to_mib {
  typeset decimal_places="${2-3}"
  typeset -lE round_bias=0.0

  if [[ decimal_places -gt 0 ]]; then
    round_bias=$((0.5 / (10 ** decimal_places)))
  fi

  printf "%.${decimal_places}f" $(($1.0 / 1024.0 / 1024.0 + round_bias))
}

function db_size_report {
  typeset -li used=$(($2 - $3))
  typeset decimal_places="${4-3}"

  printf "%s: %d (%.${decimal_places}f MiB)\n" \
    "$1" "$2" "$(b_to_mib "$2" "$decimal_places")"
  printf "  Used: %d (%.${decimal_places}f MiB)\n" \
    "$used" "$(b_to_mib "$used" "$decimal_places")"
  printf "  Free: %d (%.${decimal_places}f MiB)\n" \
    "$3" "$(b_to_mib "$3" "$decimal_places")"
}

db_stat_path="${DB_SIZE_DB_STAT:-@SBINDIR@/slapd_db_stat}"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 *.bdb" 1>&2
  exit 1
fi

typeset -A db_stats
typeset -li db_page_size db_pages db_size db_free
typeset -li db_size_total=0 db_free_total=0

for bdb in "$@"; do
  "$db_stat_path" -d "$bdb" \
  |sed -n \
    -e 's/Underlying database //p' \
    -e 's/Number of tree //p' \
    -e 's/Number of bytes free in tree \(.*\) pages (.*)$/\1 free bytes/p' \
  |while read -r value key; do
    if [[ $value == *M ]]; then
      ## See db-*/src/env/env_stat.c:__db_dl() and __db_dl_pct()
      value=$((${value%M} * 1000 * 1000))
    fi
    db_stats[$key]="$value"
  done
  db_page_size="${db_stats[page size]}"
  ## 1 for the root page
  db_pages=$((
    1 +
    db_stats[internal pages] +
    db_stats[leaf pages] +
    db_stats[duplicate pages] +
    db_stats[overflow pages]
  ))
  db_free=$((
    db_stats[internal free bytes] +
    db_stats[leaf free bytes] +
    db_stats[duplicate free bytes] +
    db_stats[overflow free bytes]
  ))

  db_size=$((db_pages * db_page_size))
  db_size_report "$bdb" "$db_size" "$db_free"

  db_size_total+=$((db_size))
  db_free_total+=$((db_free))
done

db_size_report "Total" "$db_size_total" "$db_free_total"

