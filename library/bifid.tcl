# bifid.tcl --
#
#	Display routines for the bifid cipher type.
#
# RCS: @(#) $Id: bifid.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
#
# Copyright (C) 1998-2000  Mike Thomas <wart@kobold.org>
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

package provide ciphertool 1.3

proc display_cipher_bifid {args} {
    global cipherinfo

    if {[$cipherinfo(object) cget -period] < 1} {
	return
    }
    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    $t insert 3.end \n
    set col 0
    set row 3
    set ctext [$cipherinfo(object) cget -ct]

    set exp ".\{0,[$cipherinfo(object) cget -period]\}"
    while {[string length $ctext] > 0} {
	regexp ($exp) $ctext null word
	regsub ($exp) $ctext {} ctext
	if {[string length $word]*2 + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    $t insert [expr {$row+1}].end "\n"
	    $t insert [expr {$row+2}].end "\n"
	    $t insert [expr {$row+3}].end "\n"
	    $t insert [expr {$row+4}].end "\n"
	    $t insert [expr {$row+5}].end "\n"
	    set col 0
	    incr row 5
	}
	foreach el [split $word {}] {
	    $t insert $row.$col "$el " ct
	    incr col 2
	}
	$t insert $row.$col {  }
	incr col 2
    }
    $t insert [expr {$row+1}].end "\n"
    $t insert [expr {$row+2}].end "\n"
    incr row 3

    $t configure -height $row

    $t configure -state disabled
}

proc clear_key_bifid {args} {
    global cipherinfo

    $cipherinfo(object) undo abcdefghiklmnopqrstuvwxyz

    display_cipher
}

proc do_sub_bifid {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	$cipherinfo(object) undo $cipherinfo(sub,pt)
    } else {
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,offset)\
		$cipherinfo(sub,pt)
    }

    display_pt $cipherinfo(sub,ct)
}

proc display_pt_bifid {{ct {}}} {
    global cipherinfo

    if {[$cipherinfo(object) cget -period] < 1} {
	return
    }
    set t $cipherinfo(text)

    $t configure -state normal

    set col 0
    set row 4

    # Redisplay the bifid text
    foreach {start end} [$t tag ranges bt] {
	$t delete $start $end
    }
    set btext [$cipherinfo(object) cget -btext]
    set exp [string repeat . [$cipherinfo(object) cget -period]]
    set exp ".\{0,[expr [$cipherinfo(object) cget -period]*2]\}"
    while {[string length $btext] > 0} {
	regexp ($exp) $btext null word
	regsub ($exp) $btext {} btext
	set midpoint [expr [string length $word] / 2]
	set word2 [string range $word $midpoint end]
	incr midpoint -1
	set word1 [string range $word 0 $midpoint]

	if {[string length $word1]*2 + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    set col 0
	    incr row 5
	}
	foreach el1 [split $word1 {}] el2 [split $word2 {}] {
	    $t insert $row.$col "$el1 " bt
	    $t insert [expr $row+1].$col "$el2 " bt
	    incr col 2
	}
	$t insert $row.$col {  } bt
	$t insert [expr $row+1].$col {  } bt
	incr col 2
    }

    # Redisplay the plaintext
    foreach {start end} [$t tag ranges pt] {
	$t delete $start $end
    }
    set col 0
    set row 2
    set ptext [$cipherinfo(object) cget -ptext]
    set exp ".\{0,[$cipherinfo(object) cget -period]\}"
    while {[string length $ptext] > 0} {
	regexp ($exp) $ptext null word
	regsub ($exp) $ptext {} ptext

	if {[string length $word]*2 + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    set col 0
	    incr row 5
	}
	foreach el [split [string toupper $word] {}] {
	    $t insert $row.$col "$el " pt
	    incr col 2
	}
	$t insert $row.$col {  } pt
	incr col 2
    }

    $t configure -state disabled
}

proc display_key_bifid {w args} {
    global cipherinfo

    $w configure -state normal

    set key [$cipherinfo(object) cget -key]

    # Reconstruct the key square.
    for {set row 0} {$row <= 5} {incr row} {
	for {set col 0} {$col <= 5} {incr col} {
	    set keysquare($row,$col) {}
	}
    }
    foreach letter [split [lindex $key 0] {}] \
	    {row col} [split [lindex $key 1] {}] {
	# The bifid internals should guarantee us that there are
	# never two letters allocated to the same (compltete) key
	# cell.  "lappend" is used here instead of "set" so that
	# so that we can save all of the letters allocated to _incomplete_
	# key cells.
	lappend keysquare($row,$col) $letter
    }

    $w configure -width 28 -height 7

    $w delete 0.0 end

    $w insert 0.0 \n
    $w insert 1.end "   1 2 3 4 5\n"

    for {set row 2} {$row < 7} {incr row} {
	set keyRow [expr $row - 1]
	$w insert $row.end " $keyRow"
	for {set keyCol 1} {$keyCol <= 5} {incr keyCol} {
	    set el $keysquare($keyRow,$keyCol)
	    if {$el == {}} {
		set el { }
	    }
	    $w insert $row.end " $el"
	}
	foreach el $keysquare($keyRow,0) {
	    $w insert $row.end " $el"
	}
	$w insert $row.end "\n"
    }
    set hasMoreCells 1
    for {set hasMoreCells 1; set maxCellCount 0} \
	    {$hasMoreCells} \
	    {incr maxCellCount} {
	set hasMoreCells 0
	$w insert $row.end "  "
	for {set keyCol 1} {$keyCol <= 5} {incr keyCol} {
	    set letter [lindex $keysquare(0,$keyCol) $maxCellCount]
	    if {$letter != {}} {
		$w insert $row.end " $letter"
		set hasMoreCells 1
	    } else {
		$w insert $row.end "  "
	    }
	}
	if {$hasMoreCells} {
	    $w insert $row.end "\n"
	    incr row
	}
    }

    $w configure -height $row
    $w configure -state disabled
}

proc create_input_bifid {w args} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w
	#
	# The Period input area
	#
	frame	$w.period
	label	$w.period.label -text "Period"
	entry	$w.period.entry -width 10 -textvariable cipherinfo(sub,period)
	bind	$w.period.entry <Return> { set_period }
	pack	$w.period.label -side left -fill x
	pack	$w.period.entry -side left -fill x
	pack	$w.period -side top -fill x

	#
	# The row input area
	#
	frame	$w.row
	label	$w.row.label -text "Row:"
	entry	$w.row.entry -width 10 -textvariable cipherinfo(sub,ct)
	create_radio_buttons $w.row.r cipherinfo(sub,ct) "0 1 2 3 4 5"
	pack	$w.row.label -side left -fill x
	pack	$w.row.entry -side left -fill x
	pack	$w.row.r -side left
	pack	$w.row -side top -fill x

	#
	# The column input area
	#
	frame	$w.column
	label	$w.column.label -text "Column:"
	entry	$w.column.entry -width 10 -textvariable cipherinfo(sub,offset)
	create_radio_buttons $w.column.r cipherinfo(sub,offset) "0 1 2 3 4 5"
	pack	$w.column.label -side left -fill x
	pack	$w.column.entry -side left -fill x
	pack	$w.column.r -side left
	pack	$w.column -side top -fill x

	#
	# The plaintext input area
	#
	frame	$w.pt
	label	$w.pt.label -text "Value:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	create_radio_buttons $w.pt.r cipherinfo(sub,pt) a-z
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt.r -side left
	pack	$w.pt -side top -fill x

	#
	# The Locate tip input area
	#
	frame	$w.lframe
	label	$w.lframe.ptlabel -text "Tip:"
	entry	$w.lframe.pt -textvariable cipherinfo(sub,pt)
	label	$w.lframe.ctlabel -text "Start at:"
	entry	$w.lframe.ct -textvariable cipherinfo(sub,ct)
	pack	$w.lframe.ptlabel $w.lframe.pt -side left
	pack	$w.lframe.ctlabel $w.lframe.ct -side left
	pack	$w.lframe -side top -fill x

	$w.period.label configure -width 8
	$w.column.label configure -width 8
	$w.row.label configure -width 8
	$w.pt.label configure -width 8
    }
}

proc save_cipher_bifid {chanid} {
    global cipherinfo

#    puts $chanid "# K1 Key:  [lindex [$cipherinfo(object) cget -K1key] 1]"
#    puts $chanid "#          abcdefghijklmnopqrstuvwxyz"
#    puts $chanid "# K2 Key:  [lindex [$cipherinfo(object) cget -K2key] 1]"
}
