# baconian.tcl --
#
#	Display routines for the baconian cipher type.
#
# RCS: @(#) $Id: baconian.tcl,v 1.3 2004/11/26 02:20:12 wart Exp $
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

proc display_cipher_baconian {args} {
    global cipherinfo

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    set col 0
    set row 3
    set ctext [$cipherinfo(object) cget -ct]

    while {[regexp (.....) $ctext null word]} {
	regsub ..... $ctext {} ctext
	if {[string length $word] + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    $t insert [expr {$row+1}].end "\n"
	    $t insert [expr {$row+2}].end "\n"
	    $t insert [expr {$row+3}].end "\n"
	    $t insert [expr {$row+4}].end "\n"
	    set col 0
	    incr row 4
	}

	set start $col
	foreach el [split $word {}] {
	    if {$col == $start + 2} {
		$t insert [expr {$row-2}].$col { } "pt pt.$word"
	    } else {
		$t insert [expr {$row-2}].$col { }
	    }
	    $t insert [expr {$row-1}].$col { } "pt $el pt.$el"

	    $t insert $row.$col $el ct
	    $t tag add ct.$el $row.$col
	    $t tag add $el $row.$col
	    $t tag add ct.$word $row.$col
	    incr col
	}
	$t insert [expr {$row-2}].$col { }
	$t insert [expr {$row-1}].$col { }
	$t insert $row.$col { }
	incr col
    }

    $t configure -state disabled
}

proc clear_key_baconian {args} {
    global cipherinfo

    $cipherinfo(object) undo abcdefghijklmnopqrstuvwxyz

    display_cipher
}

proc do_sub_baconian {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	$cipherinfo(object) undo $cipherinfo(sub,ct)
    } else {
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,pt)
    }

    display_pt $cipherinfo(sub,ct)
}

proc display_pt_baconian {{ct {}}} {
    global cipherinfo
    array set alphabet {
	0 a 1 b 2 c 3 d 4 e 5 f 6 g 7 h 8 i 9 j 10 k 11 l 12 m 13 n 14 o 15 p
	16 q 17 r 18 s 19 t 20 u 21 v 22 w 23 x 24 y 25 z}
    foreach el [array names alphabet] { set alphabet($alphabet($el)) $el }

    #
    # Use ".t tag ranges tagName to locate the positions of the ct values
    #
    set t $cipherinfo(text)
    $t configure -state normal
    set pt [split [$cipherinfo(object) cget -pt] {} ]
    set key_ct [lindex [$cipherinfo(object) cget -key] 1]

    set key_ct [split $key_ct {}]

    for {set i 0} {$i < [llength $key_ct]} {incr i} {
	set ct_key($alphabet($i)) [lindex $key_ct $i]
    }
    set ct_list [array names ct_key]
    if {![string match $ct {}]} {
	set ct_list [split $ct {}]
    }
    foreach ct $ct_list {
	set pt $ct_key($ct)
	foreach {start end} [$t tag ranges ct.$ct] {
	    regexp (\[0-9\]+)\\.(\[0-9\]+) $start null row start_col
	    regexp (\[0-9\]+)\\.(\[0-9\]+) $end null row end_col
	    incr row -1

	    for {set col $start_col} {$col < $end_col} {incr col} {

		$t delete $row.$col
		$t insert $row.$col $pt pt
		$t tag add pt.ct.$ct $row.$col
		$t tag add $pt $row.$col
	    }
	}
    }
    set pt [split [$cipherinfo(object) cget -pt] {} ]
    if {[expr {[llength $pt] * 5}] != [string length [$cipherinfo(object) cget -ct]]} {
	error "ciphertext and solution lengths do not match up! ([llength $pt] * 5 != [string length [$cipherinfo(object) cget -ct]])"
    }

    set ctext [$cipherinfo(object) cget -ct]
    for {set i 0} {$i < [llength $pt]} {incr i} {
	set ct [string range $ctext [expr {$i*5}] [expr {($i + 1)*5 - 1}]]
	foreach {start end} [$t tag ranges ct.$ct] {
	    regexp (\[0-9\]+)\\.(\[0-9\]+) $start null row col
	    incr row -2
	    incr col 2

	    $t delete $row.$col
	    $t insert $row.$col [lindex $pt $i] pt
	    $t tag add pt.[lindex $ct $i] $row.$col
	    $t tag add pt $row.$col
	}
    }
    $t configure -state disabled
}

proc display_key_baconian {w args} {
    global cipherinfo
    array set alphabet {
	0 a 1 b 2 c 3 d 4 e 5 f 6 g 7 h 8 i 9 j 10 k 11 l 12 m 13 n 14 o 15 p
	16 q 17 r 18 s 19 t 20 u 21 v 22 w 23 x 24 y 25 z}
    foreach el [array names alphabet] { set alphabet($alphabet($el)) $el }

    $w configure -state normal

    set balph [$cipherinfo(object) cget -alphabet]
    set key [lindex [$cipherinfo(object) cget -key] 1]

    $w configure -width 28 -height 7

    $w delete 0.0 end

    $w insert 0.end \n
    $w insert 1.end " BT: "
    foreach el [split $key {}] {
	$w insert 1.end " "
	$w insert 1.end $el
    }
    $w insert 1.end \n
    $w insert 2.0 "      a b c d e f g h i j k l m n o p q r s t u v w x y z\n"
    $w insert 3.end \n
    $w insert 3.end \n
    for {set i 0} {$i < 13} {incr i} {
	$w insert 4.end "   $alphabet($i)  "
    }
    $w insert 4.end \n
    for {set i 0} {$i < 13} {incr i} {
	$w insert 5.end " [lindex $balph $i]"
    }
    $w insert 5.end \n
    for {set i 13} {$i < 26} {incr i} {
	$w insert 6.end "   $alphabet($i)  "
    }
    $w insert 6.end \n
    for {set i 13} {$i < 26} {incr i} {
	$w insert 7.end " [lindex $balph $i]"
    }
    $w insert 7.end \n

    $w configure -state disabled
}

proc create_input_baconian {w args} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w
	#
	# The Plaintext input area
	#
	frame	$w.pt
	label	$w.pt.label -text "PText:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	create_radio_buttons $w.pt.r cipherinfo(sub,pt) {a b}
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt.r -side left
	#
	# The Ciphertext input area
	#
	frame	$w.ct
	label	$w.ct.label -text "CText:"
	entry	$w.ct.entry -width 10 -textvariable cipherinfo(sub,ct)
	create_radio_buttons $w.ct.r cipherinfo(sub,ct) a-z
	pack	$w.ct.label -side left -fill x
	pack	$w.ct.entry -side left -fill x
	pack	$w.ct.r -side left

	$w.ct.label configure -width 8
	$w.pt.label configure -width 8
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
	pack	$w.pt -side top -fill x
	pack	$w.ct -side top -fill x
	pack	$w.lframe -side top -fill x
    }
}

proc save_cipher_baconian {chanid} {
    global cipherinfo

    set btext [$cipherinfo(object) cget -btext]
    puts -nonewline $chanid "# BT:\t"
    while {[regexp (.....) $btext null word]} {
	regsub ..... $btext {} btext
	puts -nonewline $chanid "$word "
    }
}
