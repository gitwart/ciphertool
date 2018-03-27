#!/bin/sh
# \
exec tclsh "$0" ${1+"$@"}

# hillclimb --
#
#	Hill climbing autosolver for a variety of cipher types.
#
# RCS: @(#) $Id: vigenere.tcl,v 1.2 2004/09/08 14:42:09 wart Exp $
#
# Copyright (C) 2001-2002  Mike Thomas <wart@kobold.org>
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
package require CipherUtil
package require Hillclimb
package require Tk

if {[llength $argv] == 0} {
    puts stderr "Usage:  $argv0 cipherfile type ?period? ?fixedKeyword?"
    exit 1
}

set filename [lindex $argv 0]
set type [lindex $argv 1]
set period [lindex $argv 2]
set fixedKeyword [lindex $argv 3]

set ct [CipherUtil::readCiphertext $filename]

if {$type == "aristocrat"} {
    regsub -all { } $ct {} ct
}

set outfileid [open $filename.csol w]
fconfigure $outfileid -buffering line

if {$period != "" && $period > 0} {
    set c [cipher create $type -ct $ct -period $period]
} else {
    set c [cipher create $type -ct $ct]
}

if {[info exists ::env(CIPHER_LANGUAGE)]} {
    $c configure -language $::env(CIPHER_LANGUAGE)
    puts "Using language=[$c cget -language]"
}

# Iterate over all possible keys

catch {[$c configure -bestfitcommand show_best_fit -stepcommand show_fit -stepinterval $stepInterval]}

set Hillclimb::neighborProc $Hillclimb::swapKeyProc($type)
set Hillclimb::decipherProc $Hillclimb::decipherProcFromType($type)
set Hillclimb::stepInterval 0
set Hillclimb::stepCommand {}
set Hillclimb::bestFitCommand {}
set Hillclimb::mutationAmount 20
set Hillclimb::cipherObject $c
set stepInterval 10
set maxValue 0
set maxKey {}

set menubar [frame .menubar]
menubutton $menubar.file -text File -menu $menubar.file.menu
menu $menubar.file.menu -tearoff 0
$menubar.file.menu add command -label "Start" -command doStart
$menubar.file.menu add command -label "Exit" -command exit
button $menubar.mutebutton -text "Mutate" \
	-command {doMutate}
entry $menubar.muteentry -textvariable ::Hillclimb::mutationAmount
grid columnconfigure $menubar 0 -weight 1
grid $menubar.file -row 0 -col 0 -sticky w
grid $menubar.mutebutton -row 0 -column 1
grid $menubar.muteentry -row 0 -column 2

set textbase [frame .textbase]
text $textbase.text -width 80 -height 20 \
	-xscrollcommand "$textbase.xscroll set" \
	-yscrollcommand "$textbase.yscroll set" \
	-bg white \
	-wrap none
set widget(text) $textbase.text
set widget(text,height) 0
scrollbar $textbase.yscroll -orient vert -command "$widget(text) yview"
scrollbar $textbase.xscroll -orient horiz -command "$widget(text) xview"
grid $textbase.text -row 0 -column 0 -sticky news
grid $textbase.yscroll -row 0 -column 1 -sticky ns
grid $textbase.xscroll -row 1 -column 0 -sticky we
grid columnconfigure $textbase 0 -weight 1
grid rowconfigure $textbase 0 -weight 1

set statusbase [frame .statusbase]
label $statusbase.l -textvariable widget(status) \
	-relief sunken \
	-font fixed \
	-justify left \
	-anchor w
label $statusbase.max -textvariable widget(maxkey) \
	-relief sunken \
	-font fixed \
	-justify left \
	-anchor w
grid $statusbase.l -row 0 -col 0 -sticky ew
grid $statusbase.max -row 1 -col 0 -sticky ew
grid columnconfigure $statusbase 0 -weight 1

grid columnconfigure . 0 -weight 1
grid rowconfigure . 1 -weight 1
grid $menubar -row 0 -column 0 -sticky we
grid $textbase -row 1 -column 0 -sticky news
grid $statusbase -row 2 -column 0 -sticky we

proc Hillclimb::registerMaxKey {key pt value limitvalue depth count} {
    global widget
    global maxValue

    if {$depth > $widget(text,height)} {
	for {set i $widget(text,height)} {$i < $depth} {incr i} {
	    $widget(text) insert $i.end \n
	}
	set widget(text,height) $depth
    }
    $widget(text) delete $depth.0 $depth.end

    $widget(text) insert $depth.end "$depth ($count):\t$value ($limitvalue)\t$key $pt"
    for {set i [expr {$depth+1}]} {$i <= $widget(text,height)} {incr i} {
	$widget(text) delete $i.0 $i.end
    }

    if {$value >= $maxValue} {
	set maxValue $value
	set widget(status) "$depth:\t$value"
	set widget(maxkey) "$value\t$key $pt"
    }

    update
}

proc doMutate {} {
    set ::Hillclimb::mutationRequested 1
}

proc doStart {} {
    global fixedKeyword
    global maxKey
    global type
    global decipherProc
    global c

    set curIteration 0
    set Hillclimb::curIteration 0
    set pt [$Hillclimb::decipherProc $c $fixedKeyword]

    foreach {bestKey val} [Hillclimb::recstart $fixedKeyword [score value [$Hillclimb::decipherProc $c $fixedKeyword]] 0] {}
    while {$::Hillclimb::mutationRequested} {
	set newFixedKey [::Hillclimb::mutate $fixedKeyword $::Hillclimb::mutationAmount]
	tk_dialog .foo "Mutation!" "Mutation succeeded.\n$fixedKeyword\n$newFixedKey" info 0 Ok
	set fixedKeyword $newFixedKey
	set ::Hillclimb::mutationRequested 0
	foreach {bestKey val} [Hillclimb::recstart $fixedKeyword [score value [$Hillclimb::decipherProc $c $fixedKeyword]] 0] {}
    }

# This next step has teh side effect of setting the key in the cipher
# object.

    $Hillclimb::decipherProc $c $bestKey

    foreach channel [list stdout] {
	puts $channel "#=========="
	puts $channel ""
	puts $channel "type	[list [$c cget -type]]"
	puts $channel "period	[list [$c cget -period]]"
	puts $channel "key	[list [$c cget -key]]"
	puts $channel "plaintext	[list [$c cget -pt]]"
	puts $channel "ciphertext	[list [$c cget -ct]]"
	catch {puts $channel "keyword	[list [$c cget -keyword]]"}
	puts $channel "#Score value:  [score value [$c cget -pt]]"
	puts $channel ""
	puts $channel "#=========="
    }
}
