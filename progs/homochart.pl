#!/bin/sh
# \
exec perl "$0" ${1+"$@"}

# homochart.pl --
#
#	Print a chart of the number frequencies for a homophonic cipher.
#
# RCS: @(#) $Id: homochart.pl,v 1.2 2004/09/08 16:57:49 wart Exp $
#
# Copyright (C) 1995-2000  Mike Thomas <wart@kobold.org>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

$datafile = $ARGV[0];

if ($datafile) {
    open(DATA, "$datafile") || die("Could not open $datafile for reading\n");

    while (<DATA>) {
	@numarr = split;

	foreach $num (@numarr) {
	    $num =~ s/^0+//;
	    if ($num == 0) {
		$num = 100;
	    }
	    $hist{$num}++;
	}
    }

    close (DATA);
}

for(1..25) {
    $val = $_;

    $elem = sprintf("%3d: %2s   ", $val, ($hist{$val}?$hist{$val}:" "));
    print "$elem";

    $val += 25;
    $elem = sprintf("%3d: %2s   ", $val, ($hist{$val}?$hist{$val}:" "));
    print "$elem";

    $val += 25;
    $elem = sprintf("%3d: %2s   ", $val, ($hist{$val}?$hist{$val}:" "));
    print "$elem";

    $val += 25;
    $elem = sprintf("%3d: %2s   ", $val, ($hist{$val}?$hist{$val}:" "));
    print "$elem";

    print "\n";
}
