# cadenus.tcl --
#
#	Display routines for the cadenus cipher type.
#
# RCS: @(#) $Id: cadenus.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_cadenus {args} {
    global cipherinfo

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    set col 0
    set row 3
    set maxrow [$cipherinfo(object) cget -period]

    ;#
    ;# This is slightly different than the other ciphers.  Our
    ;# key will be dislayed at the to of the columns.
    ;#

    $t insert $row.0 {   }
    for {set i 0} {$i < $maxrow} {incr i} {
	$t insert $row.[expr {$i+3}] { } key.$i
    }
    $t insert $row.end \n
    incr row
    $t insert $row.0 {   }
    for {set i 0} {$i < $maxrow} {incr i} {
	$t insert $row.[expr {$i+3}] - key.$i
    }

    display_pt_cadenus

    $t configure -state disabled
}

proc clear_key_cadenus {args} {
    global cipherinfo

    $cipherinfo(object) undo

    display_cipher
}

proc do_sub_cadenus {args} {
    error "This option not available for cadenus ciphers"
}

proc display_pt_cadenus {{ct {}}} {
#    puts -->[info level 0]
    global cipherinfo

    set t $cipherinfo(text)
    $t configure -state normal
    $t configure -height 30

    set ptext [$cipherinfo(object) cget -pt]
    set maxcol [$cipherinfo(object) cget -period]
    set key [$cipherinfo(object) cget -key]

    for {set i 0} {$i < $maxcol} {incr i} {
	set order [string index [lindex $key 1] $i]
	set indices [$t tag nextrange key.$i 0.0]
	if {"$indices" == ""} break
	set start [lindex $indices 0]
	set end [lindex $indices 1]
	$t delete $start $end
	$t insert $start [string index [lindex $key 0] $i]
	$t tag add key.$i $start
    }

    set startrow 5

    $t delete $startrow.0 end
    $t insert [expr {$startrow-1}].end \n
    for {set i 0} {$i < 25} {incr i} {
	$t insert [expr {$i + $startrow}].0 {   }
	for {set j 0} {$j < $maxcol} {incr j} {
	    set pt [string index $ptext [expr {$i*$maxcol + $j}]]
	    set row [expr {$i+$startrow}]
	    set col [expr {$j+3}]

	    $t insert $row.$col $pt
	}
	$t insert [expr {$i + $startrow}].end \n
    }

    $t configure -state disabled
}

proc display_key_cadenus {w args} {
    global cipherinfo

    set t $cipherinfo(text)

    set key [$cipherinfo(object) cget -key]
    set maxcol [$cipherinfo(object) cget -period]

    #;
    #; First update the key in the text window.  I'm not sure
    #; if this is really necessary...
    #;

    for {set i 0} {$i < $maxcol} {incr i} {
	set order [string index [lindex $key 1] $i]
	set indices [$t tag nextrange key.$i 0.0]
	if {"$indices" == ""} break
	set start [lindex $indices 0]
	set end [lindex $indices 1]
	$t delete $start $end
	$t insert $start [string index [lindex $key 0] $i]
	$t tag add key.$i $start
    }

    $w delete 0.0 end
    $w insert 1.end \n
    for {set i 0} {$i < $maxcol} {incr i} {
	$w insert 2.end "[string index [lindex $key 0] $i] "
    }
    $w insert 2.end \n
    for {set i 0} {$i < $maxcol} {incr i} {
	$w insert 3.end "[string index [lindex $key 1] $i] "
    }
    $w insert 3.end \n
}

proc swap_columns_cadenus {args} {
#    puts -->[info level 0]
    global cipherinfo

#    puts "$cipherinfo(object) swap $cipherinfo(sub,col1) $cipherinfo(sub,col2)"
    $cipherinfo(object) swap $cipherinfo(sub,col1) $cipherinfo(sub,col2)

    display_pt
}

proc fit_columns_cadenus {args} {
#    puts -->[info level 0]
    global cipherinfo

    $cipherinfo(object) fit $cipherinfo(sub,col1) $cipherinfo(sub,col2)

    display_pt
}

proc rotate_column_cadenus {args} {
#    puts -->[info level 0]
    global cipherinfo

#    puts "$cipherinfo(object) rotate $cipherinfo(sub,col1) $cipherinfo(sub,pt)"
    $cipherinfo(object) rotate $cipherinfo(sub,col1) $cipherinfo(sub,pt)

    display_pt
}

proc create_input_cadenus {w {bbar {}}} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w
	#
	# The Plaintext input area
	#
	frame	$w.pt
	label	$w.pt.label -text "Amount:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	create_radio_buttons $w.pt.r cipherinfo(sub,pt) a-z
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt -side top -fill x
	#
	# The Ciphertext input area
	#
#	frame	$w.ct
#	label	$w.ct.label -text "CText:"
#	entry	$w.ct.entry -width 10 -textvariable cipherinfo(sub,ct)
#	create_radio_buttons $w.ct.r cipherinfo(sub,ct) a-z
#	pack	$w.ct.label -side left -fill x
#	pack	$w.ct.entry -side left -fill x
#	pack	$w.ct -side top -fill x

	frame	$w.col
	frame	$w.col.col1
	frame	$w.col.col2
	label	$w.col.col1.label -text "Column 1:"
	entry	$w.col.col1.entry -width 10 -textvariable cipherinfo(sub,col1)
	label	$w.col.col2.label -text "Column 2:"
	entry	$w.col.col2.entry -width 10 -textvariable cipherinfo(sub,col2)
	pack	$w.col.col1.label -side left -fill x
	pack	$w.col.col1.entry -side left -fill x
	pack	$w.col.col2.label -side left -fill x
	pack	$w.col.col2.entry -side left -fill x
	pack	$w.col.col1 -side left -fill x
	pack	$w.col.col2 -side left -fill x
	pack	$w.col -side top -fill x

	button	$bbar.swap -text "Swap columns" -command swap_columns_cadenus
	button	$bbar.fit -text "Fit columns" -command fit_columns_cadenus
	button	$bbar.rotate -text "Rotate column" -command rotate_column_cadenus
	pack	$bbar.swap $bbar.rotate $bbar.fit -side left

#	$w.ct.label configure -width 9
	$w.pt.label configure -width 9
	$w.col.col1.label configure -width 9
    }
}

proc solve_cipher_cadenus {args} {
    global cipherinfo

    $cipherinfo(object) solve

    display_pt
}

proc save_cipher_cadenus {chanid} {
}
