# columnar.tcl --
#
#	Display routines for the columnar cipher type.
#
# RCS: @(#) $Id: columnar.tcl,v 1.3 2004/09/08 17:05:00 wart Exp $
#
# Copyright (C) 1998-2002  Mike Thomas <wart@kobold.org>
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

proc display_cipher_columnar {args} {
    global cipherinfo

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    set col 0
    set row 3
    set maxrow [$cipherinfo(object) cget -period]
    set key [$cipherinfo(object) cget -key]

    #
    # This is slightly different than the other ciphers.  Our
    # key will be dislayed at the to of the columns.
    #

    $t insert $row.0 {   }
    for {set i 0} {$i < $maxrow} {incr i} {
	$t insert $row.[expr {$i+3}] { } [list columnar_col col_$i]
    }
    $t insert $row.end \n
    incr row
    $t insert $row.0 {   }
    for {set i 0} {$i < $maxrow} {incr i} {
	$t insert $row.[expr {$i+3}] - [list columnar_col col_$i]
    }

    display_pt_columnar

    $t configure -state disabled
}

proc clear_key_columnar {args} {
    global cipherinfo

    $cipherinfo(object) undo

    display_cipher
}

proc do_sub_columnar {args} {
    error "This option not available for columnar ciphers"
}

proc do_shift_columnar {column amount} {
    global cipherinfo
    set key [$cipherinfo(object) cget -key]

    $cipherinfo(object) shift [string index $key $column] $amount

    display_cipher
}

proc display_pt_columnar {{ct {}}} {
#    puts -->[info level 0]
    global cipherinfo

    set t $cipherinfo(text)
    $t configure -state normal
    $t configure -height 30

    set ptext [$cipherinfo(object) cget -pt]
    set maxcol [$cipherinfo(object) cget -period]
    set key [$cipherinfo(object) cget -key]

    # Display the key across the top of the plaintext columns
    for {set i 0} {$i < $maxcol} {incr i} {
	set order [string index [lindex $key 1] $i]
	set indices [$t tag nextrange col_$i 0.0]
	if {"$indices" == ""} break
	set start [lindex $indices 0]
	set end [lindex $indices 1]
	$t delete $start $end
	$t insert $start [string index [lindex $key 0] $i]
	$t tag add col_$i $start
	$t tag add columnar_col $start
    }

    # Now display the plaintext array.
    set startrow 5

    $t delete $startrow.0 end
    $t insert [expr {$startrow-1}].end \n
    for {set i 0} {$i < 25} {incr i} {
	$t insert [expr {$i + $startrow}].0 {   }
	for {set j 0} {$j < $maxcol} {incr j} {
	    set pt [string index $ptext [expr {$i*$maxcol + $j}]]
	    set row [expr {$i+$startrow}]
	    set col [expr {$j+3}]

	    $t insert $row.$col $pt [list columnar_col col_$j]
	}
	$t insert [expr {$i + $startrow}].end \n
    }

    $t configure -state disabled
}

proc display_key_columnar {w args} {
    global cipherinfo

    set t $cipherinfo(text)

    set key [$cipherinfo(object) cget -key]
    set maxcol [$cipherinfo(object) cget -period]

    #
    # First update the key in the text window.  I'm not sure
    # if this is really necessary...
    #

    for {set i 0} {$i < $maxcol} {incr i} {
	set order [string index [lindex $key 1] $i]
	set indices [$t tag nextrange col_$i 0.0]
	if {"$indices" == ""} break
	set start [lindex $indices 0]
	set end [lindex $indices 1]
	$t delete $start $end
	$t insert $start [string index [lindex $key 0] $i]
	$t tag add col_$i $start
	$t tag add columnar_col $start
    }

    $w delete 0.0 end
    $w insert 1.end \n
    for {set i 0} {$i < $maxcol} {incr i} {
	$w insert 2.$i [string index [lindex $key 0] $i]
    }
    $w insert 2.end \n
}

proc swap_columns_columnar {args} {
    global cipherinfo

    $cipherinfo(object) swap $cipherinfo(sub,col1) $cipherinfo(sub,col2)

    display_pt
}

proc solve_cipher_columnar {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc create_input_columnar {w {bbar {}}} {
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
	$w.col.col1.label configure -width 9
    }
}

proc set_bindings_columnar {wid} {
    global cipherinfo
    $wid tag configure col_selected -background yellow

    # Tag for selecing a column to drag.
    $wid tag bind columnar_col <ButtonPress-1> {
	set tagList [%W tag names @%x,%y]
	set col {}
	foreach tag $tagList {
	    if {[regexp {^col_([0-9]+)} $tag null col]} {
	    }
	}
	%W tag remove col_selected 0.0 end
	foreach {start end} [%W tag ranges col_$col] {
	    %W tag add col_selected $start
	}
	set cipherinfo(sub,ct) $col
	set cipherinfo(sub,pt) 0
	break
    }

    # Tag for dragging a column
    $wid tag bind columnar_col <B1-Motion> {
	set tagList [%W tag names @%x,%y]
	set col {}
	foreach tag $tagList {
	    if {[regexp {^col_([0-9]+)} $tag null col]} {
	    }
	}
	if {$col == ""} {
	    break
	}
	set cipherinfo(sub,pt) [expr {$col - $cipherinfo(sub,ct)}]
	if {$col != $cipherinfo(sub,ct)} {
	    do_shift_columnar $cipherinfo(sub,ct) $cipherinfo(sub,pt)
	    %W tag remove col_selected 0.0 end
	    foreach {start end} [%W tag ranges col_$col] {
		%W tag add col_selected $start
	    }
	    set cipherinfo(sub,ct) $col
	    set cipherinfo(sub,pt) 0
	}
	break
    }

    # Tag for dropping a column to a new position
    $wid tag bind columnar_col <ButtonRelease-1> {
	%W tag remove col_selected 0.0 end
	break
    }

    # Don't update the X selection while we're dragging a column around.
    bind $wid <B1-Motion> {
	if {[llength [%W tag ranges col_selected]] > 0} {
	    break
	}
    }
}

proc save_cipher_columnar {chanid} {
}
