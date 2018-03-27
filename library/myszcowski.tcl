# myszcowski.tcl --
#
#	Display routines for the myszcowski cipher type.
#
# RCS: @(#) $Id: myszcowski.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_myszcowski {args} {
    eval display_cipher_columnar $args
}

proc clear_key_myszcowski {args} {
    eval clear_key_columnar $args
}

proc do_sub_myszcowski {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	error "Missing ciphertext for substitution"
    }
    if {[string match $cipherinfo(sub,col1) {}]} {
	error "Missing value for column"
    }

    puts "$cipherinfo(object) sub $cipherinfo(sub,col1) $cipherinfo(sub,pt)"
    $cipherinfo(object) sub $cipherinfo(sub,col1) $cipherinfo(sub,pt)

    display_pt
}

proc display_pt_myszcowski {{ct {}}} {
    eval display_pt_columnar $ct
}

proc display_key_myszcowski {w args} {
    eval display_key_columnar $w $args
}

proc swap_columns_myszcowski {args} {
    eval swap_columns_columnar $args
}

proc solve_cipher_myszcowski {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc create_input_myszcowski {w {bbar {}}} {
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
	# The Plaintext input area
	#
	frame	$w.pt
	label	$w.pt.label -text "PText:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	create_radio_buttons $w.pt.r cipherinfo(sub,pt) a-z
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt.r -side left
	pack	$w.pt -side top -fill x

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

	button	$bbar.swap -text "Swap columns" -command swap_columns_columnar
	pack	$bbar.swap -side left

	$w.period.label configure -width 9
	$w.pt.label configure -width 9
	$w.col.col1.label configure -width 9
    }
}

proc save_cipher_myszcowski {chanid} {
}
