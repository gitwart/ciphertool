#!/bin/sh
# \
exec tclsh "$0" ${1+"$@"}

# gendocs.tcl --
#
#	entry point into the document creation code.
#
# Copyright (C) 1999-2004  Mike Thomas <wart@kobold.org>
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

package require cipher

if {[llength $argv] < 2 || [llength $argv] > 2} {
    puts stderr "Usage:  $argv0 srcdir outdir"
    exit 1
}

set srcdir [lindex $argv 0]
set outdir [lindex $argv 1]

source [file join [file dirname [info script]] template.tcl]
source [file join [file dirname [info script]] standardopts.tcl]

set infileList [glob [file join $srcdir *.tml]]

foreach infile $infileList {
    regsub {.tml$} $infile .html outfile
    set outfile [file join $outdir [file tail $outfile]]
    set fileId [open $infile r]
    set fileContents [read $fileId]
    close $fileId

    puts "Creating $outfile"

    set fileId [open $outfile w]
    puts $fileId [subst $fileContents]
    close $fileId
}
