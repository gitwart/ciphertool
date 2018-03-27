# morbit.tcl --
#
#	Display routines for the morbit cipher type.
#
# RCS: @(#) $Id: morbit.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_morbit {args} {
    global cipherinfo

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    $t insert 3.end \n
    set col 0
    set row 3
    set ctext [$cipherinfo(object) cget -ct]

    set exp .
    while {[regexp ($exp) $ctext null word]} {
	regsub ($exp) $ctext {} ctext
	if {[string length $word] + $col > [expr {[$cipherinfo(text) cget -width] -5}]} {
	    $t insert [expr {$row+1}].end "\n"
	    $t insert [expr {$row+2}].end "\n"
	    $t insert [expr {$row+3}].end "\n"
	    set col 0
	    incr row 3
	}
	foreach el [split $word {}] {
	    $t insert [expr {$row-1}].$col { } "pt $el pt.$el pt.ct.$el"
	    $t insert $row.$col $el ct
	    $t tag add ct.$el $row.$col
	    $t tag add $el $row.$col
	    incr col
	}
	$t insert [expr {$row-1}].$col { }
	$t insert $row.$col { }
	incr col
    }

    $t configure -state disabled
}

proc clear_key_morbit {args} {
    global cipherinfo

    $cipherinfo(object) undo

    display_cipher
}

proc do_sub_morbit {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	$cipherinfo(object) undo $cipherinfo(sub,ct)
    } else {
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,pt)
    }

    display_pt $cipherinfo(sub,ct)
}

proc display_pt_morbit {{ct {}}} {
    global cipherinfo

    #
    # Use ".t tag ranges tagName to locate the positions of the ct values
    #
    set t $cipherinfo(text)
    $t configure -state normal
    set key_ct [lindex [$cipherinfo(object) cget -key] 1]

#    puts "key_ct = $key_ct"

    for {set i 0} {$i < [string length $key_ct]} {incr i 2} {
	set ct_key([expr {$i / 2 + 1}]) [string range $key_ct $i [expr {$i+1}]]
    }

    set ct_list [array names ct_key]
    if {![string match $ct {}]} { set ct_list [split $ct {}] }
#    parray ct_key

    foreach ct $ct_list {
	set pt $ct_key($ct)
	set start 1.0
	while 1 {
	    set indices [$t tag nextrange pt.ct.$ct $start]
	    if {"$indices" == ""} break
	    foreach {start end} $indices break
	    eval $t delete $start $end+1c
	    $t insert $start $pt
	    $t tag add pt.ct.$ct $start
	    set start $start+1c
	}
    }

    set exp .
    set row 1
    set col 0
    $t delete $row.0 $row.end
    set ptext [$cipherinfo(object) cget -fullpt]

    while {[regexp ($exp) $ptext null word]} {
	regsub ($exp) $ptext {} ptext

	if {[string length $word] + $col > [expr {[$t cget -width] - 4}]} {
	    incr row 3
	    $t delete $row.0 $row.end
	    set col 0
	}

	foreach el [split $word {}] {
	    $t insert $row.end "$el"
	    incr col
	}
    }

    $t configure -state disabled
}

proc display_key_morbit {w args} {
    global cipherinfo

    $w configure -state normal

    set pt [lindex [$cipherinfo(object) cget -key] 0]
    set ct [lindex [$cipherinfo(object) cget -key] 1]

    $w configure -width 28 -height 5

    $w delete 0.0 end

    set exp ..
    $w insert 0.0 \n
    $w insert 1.end "  "
    while {[regexp ($exp) $ct null word]} {
	regsub ($exp) $ct {} ct
	$w insert 1.end " "
	$w insert 1.end [string index $word 0]
    }
    $w insert 1.end "\n"

    set ct [lindex [$cipherinfo(object) cget -key] 1]
    $w insert 2.end "  "
    while {[regexp ($exp) $ct null word]} {
	regsub ($exp) $ct {} ct
	$w insert 2.end " "
	$w insert 2.end [string index $word 1]
    }
    $w insert 2.end \n

    $w insert 3.end "  "
    foreach el [split $pt {}] {
	$w insert 3.end " "
	$w insert 3.end $el
    }
    $w insert 3.end \n

    $w configure -state disabled
}

proc create_input_morbit {w args} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w
	#
	# The Plaintext input area
	#
	frame	$w.pt
	label	$w.pt.label -text "PText:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	create_radio_buttons $w.pt.r cipherinfo(sub,pt) ".. .- .x -. -- -x x. x- xx"
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt.r -side left
	#
	# The Ciphertext input area
	#
	frame	$w.ct
	label	$w.ct.label -text "CText:"
	entry	$w.ct.entry -width 10 -textvariable cipherinfo(sub,ct)
	create_radio_buttons $w.ct.r cipherinfo(sub,ct) 1-9
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

proc save_cipher_morbit {chanid} {
    global cipherinfo

#    puts $chanid "# K1 Key:  [lindex [$cipherinfo(object) cget -K1key] 1]"
#    puts $chanid "#          abcdefghijklmnopqrstuvwxyz"
#    puts $chanid "# K2 Key:  [lindex [$cipherinfo(object) cget -K2key] 1]"
}
