#!/usr/bin/perl
##
## Decode base64-encoded attribute values in LDIF data
## Copyright (c) 2013-2019 SATOH Fumiyasu @ OSS Technology Corp., Japan
##               <https://www.OSSTech.co.jp/>
##               <https://GitHub.com/fumiyas/>
##
## License: GNU General Public License version 2 or later
##

use strict;
use warnings;
use Encode;
use MIME::Base64;

sub unbase64
{
  my ($name, $value_b64) = @_;

  my $value = MIME::Base64::decode($value_b64);
  my $value_utf8 = eval {
    Encode::decode_utf8(my $value_tmp=$value, Encode::FB_CROAK);
  };

  unless (!$@ && $value_utf8 =~ /\A[\p{IsPrint}\t\n\r\e]*\z/) {
    return "${name}::$value_b64";
  }

  $value =~ s/\\/\\\\/g;
  $value =~ s/\t/\\t/g;
  $value =~ s/\n/\\n/g;
  $value =~ s/\r/\\r/g;
  $value =~ s/\e/\\e/g;

  return "$name: $value\n";
}

$/ = "\n\n";
while (<>) {
  s/^(\w[\w\-]*(?:;\w[\w\-]*)*)::((?:[ \t]*[^\n]*\n)(?:[ \t]+[^\n]*\n)*)/unbase64($1, $2)/mge;
  print;
}
