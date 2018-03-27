# vigenere.tcl --
#
#	Display routines for the vigenere cipher type.
#
# RCS: @(#) $Id: vigenere.tcl,v 1.2 2004/09/08 14:42:09 wart Exp $
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

proc display_cipher_vigenere {args} {
    global cipherinfo
    array set alphabet {
	0 a 1 b 2 c 3 d 4 e 5 f 6 g 7 h 8 i 9 j 10 k 11 l 12 m 13 n 14 o 15 p
	16 q 17 r 18 s 19 t 20 u 21 v 22 w 23 x 24 y 25 z}
    foreach el [array names alphabet] { set alphabet($alphabet($el)) $el }

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    set col 0
    set row 3
    set ctext [$cipherinfo(object) cget -ct]
    set period [$cipherinfo(object) cget -period]

    if {[$cipherinfo(object) cget -period] < 1} {
	return
    }

    set exp {}
    for {set i 0} {$i < $period} {incr i} {
	append exp .
    }
    while {[string length $ctext] > 0} {
	if {[string length $ctext] < $period} {
	    set word $ctext
	    set ctext {}
	} else {
	    regexp ($exp) $ctext null word
	    regsub $exp $ctext {} ctext
	}
	if {[string length $word] + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    $t insert [expr {$row+1}].end "\n"
	    $t insert [expr {$row+2}].end "\n"
	    $t insert [expr {$row+3}].end "\n"
	    set col 0
	    incr row 3
	}
#	puts "adding $word to display at ($col, $row)"

	set start $col
	foreach el [split $word {}] {
	    $t insert [expr {$row-1}].$col { } "pt $el pt.$el"

	    $t insert $row.$col [string toupper $el] ct
	    $t tag add ct.$el $row.$col
	    $t tag add $el $row.$col
	    $t tag add ct.$word $row.$col
	    incr col
	}
	$t insert [expr {$row-1}].$col { }
	$t insert $row.$col { }
	incr col
    }

    $t configure -state disabled
}

proc clear_key_vigenere {args} {
    global cipherinfo

    for {set i 1} {$i <= [$cipherinfo(object) cget -period]} {incr i} {
	$cipherinfo(object) undo $i
    }

    display_cipher
}

proc do_sub_vigenere {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,ct) {}]} {
	error "Missing ciphertext for substitution"
    }
    if {[string match $cipherinfo(sub,offset) {}]} {
	error "Missing offset for substitution"
    }

    if {[string match $cipherinfo(sub,pt) {}]} {
	$cipherinfo(object) undo $cipherinfo(sub,offset)
    } else {
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,pt) [expr {$cipherinfo(sub,offset)}]
    }

    display_pt $cipherinfo(sub,offset)
}

proc display_pt_vigenere {{ct {}}} {
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
    set pt [$cipherinfo(object) cget -pt]
    set period [$cipherinfo(object) cget -period]

    set exp {}
    for {set i 0} {$i < $period} {incr i} {
	append exp .
    }
    set col 0
    set row 2
    while {[string length $pt] > 0} {
	if {[string length $pt] < $period} {
	    set word $pt
	    set pt {}
	} else {
	    regexp ($exp) $pt null word
	    regsub $exp $pt {} pt
	}
	if {$period + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    set col 0
	    incr row 3
	}

	set start $col
	foreach el [split $word {}] {
	    $t delete [expr {$row}].$col
	    $t insert [expr {$row}].$col $el "pt $el pt.$el"

	    $t tag add pt.$el [expr {$row}].$col
	    $t tag add $el [expr {$row}].$col
	    incr col
	}
	$t delete $row.$col
	$t insert $row.$col { }
	incr col
    }

    $t configure -state disabled
}

proc display_key_vigenere {w args} {
    global cipherinfo

    $w configure -state normal

    if {[llength $args]} {
	set key [lindex $args 0]
    } else {
	set key [lindex [$cipherinfo(object) cget -key] 0]
    }

    $w configure -width 28 -height 7

    $w delete 0.0 end

    $w insert 1.end \n
    $w insert 2.end \n
    $w insert 3.end \n
    set i 1
    foreach el [split $key {}] {
	$w insert 2.end "$el "
	$w insert 3.end "$i "
	incr i
    }
    $w insert 4.end \n

    $w configure -state disabled
}

proc locate_best_tip_vigenere {} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	error "No tip specified!"
    }

    $cipherinfo(object) locatebest $cipherinfo(sub,pt)

    display_pt
    display_key
}

proc fit_column_vigenere {} {
    global cipherinfo

    if {[string match $cipherinfo(sub,offset) {}]} {
	error "No column specified!"
    }

    $cipherinfo(object) fit $cipherinfo(sub,offset)

    display_pt
    display_key
}

proc create_input_vigenere {w {bbar {}}} {
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
	# The Column input area
	#
	frame	$w.column
	label	$w.column.label -text "Column Number:"
	entry	$w.column.entry -width 10 -textvariable cipherinfo(sub,offset)
	bind	$w.column.entry <Key-underscore> {
	    if {[catch {
		set cipherinfo(sub,offset) [expr ([%W get] + $cipherinfo(sub,period) - 2) %% $cipherinfo(sub,period) + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.column.entry <Key-minus> [bind $w.column.entry <Key-underscore>]
	bind	$w.column.entry <Key-equal> {
	    if {[catch {
		set cipherinfo(sub,offset) [expr ([%W get]) %% $cipherinfo(sub,period) + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.column.entry <Key-plus> [bind $w.column.entry <Key-equal>]
	pack	$w.column.label -side left -fill x
	pack	$w.column.entry -side left -fill x
	pack	$w.column -side top -fill x

	#
	# The Plaintext input area
	#
	frame	$w.pt
	label	$w.pt.label -text "PText:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	create_radio_buttons $w.pt.r cipherinfo(sub,pt) a-z
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

	button	$bbar.fitcol -text "Fit Column" -command fit_column_vigenere
	button	$bbar.locatebest -text "Best Tip Location" -command locate_best_tip_vigenere
	pack	$bbar.fitcol $bbar.locatebest -side left
    }
}

proc solve_cipher_vigenere {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc save_cipher_vigenere {chanid} {
}
