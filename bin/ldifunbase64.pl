#!/usr/bin/perl
##
## Decode base64-encoded attribute values in LDIF data
##
## SPDX-FileCopyrightText: 2013-2025 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##

use strict;
use warnings;
use Encode;
use MIME::Base64;

use constant TRUE => !! 1;
use constant FALSE => !! '';

sub unbase64
{
  my ($name, $value_b64, $as_comment) = @_;

  my $value = MIME::Base64::decode($value_b64);
  my $value_utf8 = eval {
    Encode::decode_utf8(my $value_tmp=$value, Encode::FB_CROAK);
  };

  if ($@) {
    my $line = "${name}::$value_b64";
    if ($as_comment) {
      return "## ${name}:: BINARY\n$line";
    }
    return $line
  }

  if ($value_utf8 !~ /\A[\p{IsPrint}\t\n\r\e]*\z/) {
    my $line = "${name}::$value_b64";
    if ($as_comment) {
      return "## ${name}:: BINARY\n$line";
    }
    return $line
  }

  $value =~ s/\\/\\\\/g;
  $value =~ s/\t/\\t/g;
  $value =~ s/\n/\\n/g;
  $value =~ s/\r/\\r/g;
  $value =~ s/\e/\\e/g;

  my $line = "$name: $value\n";
  if ($as_comment) {
    return "## $line${name}::$value_b64";
  }
  return $line
}

my $as_comment = FALSE;

if ($ARGV[0]) {
  if ($ARGV[0] eq '-h' || $ARGV[0] eq '--help') {
    print("Usage: $0 [--comment] < data.ldif\n");
    exit(0);
  }
  if ($ARGV[0] eq '--comment') {
    $as_comment = TRUE;
    shift(@ARGV);
  }
}

$/ = "\n\n";
while (<>) {
  s/^(\w[\w\-]*(?:;\w[\w\-]*)*)::((?:[ \t]*[^\n]*\n)(?:[ \t]+[^\n]*\n)*)/unbase64($1, $2, $as_comment)/mge;
  print;
}
