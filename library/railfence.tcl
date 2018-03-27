# railfence.tcl --
#
#	Display routines for the railfence cipher type.
#
# RCS: @(#) $Id: railfence.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_railfence {args} {
    eval display_cipher_myszcowski $args
}

proc clear_key_railfence {args} {
    eval clear_key_columnar $args
}

proc solve_cipher_railfence {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc do_sub_railfence {args} {
    puts -->[info level 0]
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	error "Missing ciphertext for substitution"
    }
    if {[string match $cipherinfo(sub,col1) {}]} {
	error "Missing value for column"
    }

    $cipherinfo(object) sub $cipherinfo(sub,col1) $cipherinfo(sub,pt)

    display_pt
}

proc display_pt_railfence {{ct {}}} {
    display_pt_columnar $ct
}

proc display_key_railfence {w args} {
    eval display_pt_columnar $w $args
}

proc swap_columns_railfence {args} {
    eval swap_columns_columnar $args
}

proc set_start_railfence {args} {
    global cipherinfo

    set rail $cipherinfo(sub,pt)
    set dir $cipherinfo(sub,dir)

    $cipherinfo(object) move $rail $dir

    display_pt
}

proc create_input_railfence {w {bbar {}}} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w
	#
	# The Period input area
	#
	frame	$w.period
	label	$w.period.label -text "Period:"
	entry	$w.period.entry -width 10 -textvariable cipherinfo(sub,period)
	bind	$w.period.entry <Return> { set_period }
	pack	$w.period.label -side left -fill x
	pack	$w.period.entry -side left -fill x
	pack	$w.period -side top -fill x

	#
	# The Shift amount input area
	#
	frame	$w.shift
	frame	$w.shift.pt
	label	$w.shift.pt.label -text "Shift:"
	entry	$w.shift.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	pack	$w.shift.pt.label -side left -fill x
	pack	$w.shift.pt.entry -side left -fill x
	pack	$w.shift.pt -side left -fill x

	#
	# The start rail direction input area
	#
	frame	$w.shift.dir
	label	$w.shift.dir.label -text "Direction:"
	radiobutton $w.shift.dir.up -text "Up" -value up \
		-variable cipherinfo(sub,dir)
	radiobutton $w.shift.dir.down -text "Down" -value down \
		-variable cipherinfo(sub,dir)
	pack	$w.shift.dir.label $w.shift.dir.up $w.shift.dir.down \
		-side left -anchor w
	pack	$w.shift.dir -side left
	$w.shift.dir.up select
	pack	$w.shift -side top -fill x

	frame	$w.col
	frame	$w.col.col1
	frame	$w.col.col2
	label	$w.col.col1.label -text "Rail 1:"
	entry	$w.col.col1.entry -width 10 -textvariable cipherinfo(sub,col1)
	label	$w.col.col2.label -text "Rail 2:"
	entry	$w.col.col2.entry -width 10 -textvariable cipherinfo(sub,col2)
	pack	$w.col.col1.label -side left -fill x
	pack	$w.col.col1.entry -side left -fill x
	pack	$w.col.col2.label -side left -fill x
	pack	$w.col.col2.entry -side left -fill x
	pack	$w.col.col1 -side left -fill x
	pack	$w.col.col2 -side left -fill x
	pack	$w.col -side top -fill x

	button	$bbar.swap -text "Swap columns" -command swap_columns_railfence
	button	$bbar.shift -text "Set start rail" -command set_start_railfence
	pack	$bbar.swap $bbar.shift -side left

	$w.period.label configure -width 9
	$w.shift.pt.label configure -width 9
	$w.col.col1.label configure -width 9
    }
}

proc save_cipher_railfence {chanid} {
}
