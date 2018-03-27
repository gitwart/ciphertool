# swagman.tcl --
#
#	Display routines for the swagman cipher type.
#
# RCS: @(#) $Id: swagman.tcl,v 1.4 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_swagman {args} {
    global cipherinfo

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    set col 0
    set row 3
    set ctblock [string toupper [$cipherinfo(object) cget -ctblock]]
    set ptblock [$cipherinfo(object) cget -ptblock]
    set period  [$cipherinfo(object) cget -period]
    set key     [$cipherinfo(object) cget -key]

    if {[$cipherinfo(object) cget -period] < 1} {
	return
    }

    set ptrow 0
    foreach crow $ptblock {
	incr ptrow
	foreach group $crow {
	    regsub -all { } $group - group
	    $t insert $row.end "$group " [list swagman_pt_row$ptrow]
	}
	$t insert $row.end "\n"
	incr row
    }

    $t insert $row.end "\n"
    incr row
    $t insert $row.end "\n"
    incr row

    set groupRow 0
    foreach crow $ctblock {
	incr groupRow
	foreach group $crow {
	    set groupCol 0
	    foreach letter [split $group {}] {
		incr groupCol
		$t insert $row.end "$letter" \
			[list swagman_ct swagman_ct_$groupRow,$groupCol]
	    }
	    $t insert $row.end " "
	}
	$t insert $row.end "\n"
	incr row
    }

    for {set groupRow 0} {$groupRow < $period} {incr groupRow} {
	for {set groupCol 0} {$groupCol < $period} {incr groupCol} {
	    set keyVal [string index $key \
		    [expr {$groupRow * $period + $groupCol}]]
	    if {$keyVal != " "} {
		puts "keyval is $keyVal"
		set foreground grey
	    } else {
		set foreground black
	    }
	    $t tag configure swagman_ct_$keyVal,[expr {$groupCol+1}] \
		    -foreground $foreground
	}
    }

    $t configure -state disabled
}

proc clear_key_swagman {args} {
    global cipherinfo

    $cipherinfo(object) undo

    display_cipher
}

proc do_sub_swagman {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,ct) {}]} {
	error "Missing ciphertext for substitution"
    }
    if {[string match $cipherinfo(sub,offset) {}]} {
	error "Missing offset for substitution"
    }

    if {[string match $cipherinfo(sub,pt) {}]} {
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,offset)
    } else {
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,offset) $cipherinfo(sub,pt)
    }

    display_pt
}

proc display_pt_swagman {{ct {}}} {
    display_cipher_swagman
}

proc display_key_swagman {w args} {
    global cipherinfo

    $w configure -state normal

    set key [$cipherinfo(object) cget -key]

    $w delete 0.0 end

    $w insert 1.end \n
    $w insert 2.end \n
    set row 3
    set col 0
    regsub -all -- { } $key - key
    foreach cell [split $key {}] {
	$w insert $row.end " $cell"
	incr col

	if {$col >= [$cipherinfo(object) cget -period]} {
	    $w insert $row.end "\n"
	    incr row
	    set col 0
	}
    }

    $w configure -width 10 -height $row

    $w configure -state disabled
}

proc locate_best_tip_swagman {} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	error "No tip specified!"
    }

    $cipherinfo(object) locate $cipherinfo(sub,pt)

    display_pt
    display_key
}

proc swap_columns_swagman {args} {
#    puts -->[info level 0]
    global cipherinfo

#    puts "$cipherinfo(object) swap $cipherinfo(sub,col1) $cipherinfo(sub,col2)"

    # sub,ct is really row1 

    $cipherinfo(object) swap $cipherinfo(sub,ct) $cipherinfo(sub,row2)

    display_pt
}

proc create_input_swagman {w {bbar {}}} {
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
	# The Row input area
	#
	frame	$w.row
	label	$w.row.label1 -text "Row:"
	entry	$w.row.entry1 -width 10 -textvariable cipherinfo(sub,ct)
	label	$w.row.label2 -text "Row:"
	entry	$w.row.entry2 -width 10 -textvariable cipherinfo(sub,row2)
	bind	$w.row.entry1 <Key-underscore> {
	    if {[catch {
		set cipherinfo(sub,ct) [expr ([%W get] + $cipherinfo(sub,period) - 2) %% $cipherinfo(sub,period) + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.row.entry1 <Key-minus> [bind $w.row.entry1 <Key-underscore>]
	bind	$w.row.entry1 <Key-equal> {
	    if {[catch {
		set cipherinfo(sub,ct) [expr ([%W get]) %% $cipherinfo(sub,period) + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.row.entry1 <Key-plus> [bind $w.row.entry1 <Key-equal>]
	bind	$w.row.entry2 <Key-underscore> [bind $w.row.entry1 <Key-underscore>]
	bind	$w.row.entry2 <Key-minus> [bind $w.row.entry1 <Key-minus>]
	bind	$w.row.entry2 <Key-equal> [bind $w.row.entry1 <Key-equal>]
	bind	$w.row.entry2 <Key-plus> [bind $w.row.entry1 <Key-equal>]
	pack	$w.row.label1 -side left -fill x
	pack	$w.row.entry1 -side left -fill x
	pack	$w.row.label2 -side left -fill x
	pack	$w.row.entry2 -side left -fill x
	pack	$w.row -side top -fill x

	#
	# The Column input area
	#
	frame	$w.column
	label	$w.column.label -text "Column:"
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
	# The Value input area
	#
	frame	$w.pt
	label	$w.pt.label -text "Key Val:"
	entry	$w.pt.entry -width 10 -textvariable cipherinfo(sub,pt)
	bind	$w.pt.entry <Key-underscore> {
	    if {[catch {
		set cipherinfo(sub,pt) [expr ([%W get] + $cipherinfo(sub,period) - 2) %% $cipherinfo(sub,period) + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.pt.entry <Key-minus> [bind $w.pt.entry <Key-underscore>]
	bind	$w.pt.entry <Key-equal> {
	    if {[catch {
		set cipherinfo(sub,pt) [expr ([%W get]) %% $cipherinfo(sub,period) + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.pt.entry <Key-plus> [bind $w.pt.entry <Key-equal>]
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt.label -side left -fill x
	pack	$w.pt.entry -side left -fill x
	pack	$w.pt -side top -fill x

	button	$bbar.swap -text "Swap rows" -command swap_columns_swagman
	pack	$bbar.swap -side left

	$w.period.label configure -width 8
	$w.column.label configure -width 8
	$w.row.label1 configure -width 8
	$w.row.label2 configure -width 8
	$w.pt.label configure -width 8
    }
}

proc solve_cipher_swagman {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc set_bindings_swagman {wid} {
    global cipherinfo
    $wid tag configure swagman_used_ct -foreground grey
    $wid tag configure swagman_ct_selected -foreground red

    $wid tag bind swagman_ct <ButtonPress-1> {
	set tagList [%W tag names @%x,%y]
	set row {}
	set col {}
	foreach tag $tagList {
	    if {[regexp {^swagman_ct_([0-9]+),([0-9]+)} $tag null row col]} {
	    }
	}
	%W tag remove swagman_ct_selected 0.0 end
	foreach {start end} [%W tag ranges swagman_ct_$row,$col] {
	    %W tag add swagman_ct_selected $start
	}
	#set cipherinfo(sub,ct) $row
	set cipherinfo(sub,offset) $col
	set cipherinfo(sub,pt) $row
	#puts "letter at row, col:  $row, $col"
    }

    $wid tag bind swagman_ct <B1-Motion> {
	set tagList [%W tag names @%x,%y]
	set ptrow {}
	foreach tag $tagList {
	    if {[regexp {^swagman_pt_row([0-9]+)} $tag null ptrow]} {
	    }
	}
	if {$ptrow == ""} {
	    break
	}
	set cipherinfo(sub,ct) $ptrow
	#do_sub_swagman
    }

    # Tag for dropping a column to a new position
    $wid tag bind swagman_ct <ButtonRelease-1> {
	%W tag remove swagman_ct_selected 0.0 end
	set tagList [%W tag names @%x,%y]
	set ptrow {}
	foreach tag $tagList {
	    if {[regexp {^swagman_pt_row([0-9]+)} $tag null ptrow]} {
	    }
	}
	if {$ptrow == ""} {
	    break
	}
	set cipherinfo(sub,ct) $ptrow
	do_sub_swagman
	break
    }

    # Don't update the X selection while we're dragging a column around.
    bind $wid <B1-Motion> {
	if {[llength [%W tag ranges swagman_ct_selected]] > 0} {
	    break
	}
    }
}

proc save_cipher_swagman {chanid} {
    global cipherinfo

    set pt [$cipherinfo(object) cget -ptblock]
    for {set i 0} {$i < [$cipherinfo(object) cget -period]} {incr i} {
	puts $chanid "# PT:  [lindex $pt $i]"
    }

    set ct [$cipherinfo(object) cget -ctblock]
    for {set i 0} {$i < [$cipherinfo(object) cget -period]} {incr i} {
	puts $chanid "# CT:  [lindex $ct $i]"
    }

    set key [$cipherinfo(object) cget -key]
    for {set i 0} {$i < [$cipherinfo(object) cget -period]} {incr i} {
	puts $chanid "# Key:  [lindex $key $i]"
    }
}
