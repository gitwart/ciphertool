# grille.tcl --
#
#	Display routines for the grille cipher type.
#
# RCS: @(#) $Id: grille.tcl,v 1.3 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_grille {args} {
    global cipherinfo

    set t $cipherinfo(text)

    $t configure -state normal

    $t delete 0.0 end

    $t insert 1.end \n
    $t insert 2.end \n
    set col 0
    set row 3
    set ct [$cipherinfo(object) cget -ct]
    set pt [$cipherinfo(object) cget -pt]
    set ptblock [$cipherinfo(object) cget -ptblock]
    set period [$cipherinfo(object) cget -period]
    set key [$cipherinfo(object) cget -key]

    if {[$cipherinfo(object) cget -period] < 1} {
	return
    }

    regsub -all { } $pt . pt
    $t insert $row.end "  $pt\n"
    incr row

    $t insert $row.end "\n"
    incr row

    set rowpattern [string repeat . $period]
    set blockpattern [string repeat . [expr {$period * $period}]]

    set cipherrow 1
    while {[regexp $rowpattern $ct rowct]} {
	regsub $rowpattern $ct {} ct
	$t insert $row.end "  "
	set ciphercol 1
	foreach char [split $rowct {}] {
	    set keyIndex [expr {($cipherrow-1) * $period + ($ciphercol-1)}]
	    set tagList [list pos=$cipherrow,$ciphercol grille_ctgrid]
	    # Tag the position based on if it's a hole in any of the 4
	    # grille positions.
	    if {[string index $key $keyIndex] != 0} {
		lappend tagList grille_hole_[string index $key $keyIndex]
	    }

	    $t insert $row.end $char $tagList
	    $t insert $row.end " "
	    incr ciphercol
	}
	$t insert $row.end "\n"
	#$t insert $row.end "  [join [split $rowct {}] { }]\n"
	incr row
	incr cipherrow
    }
    $t insert $row.end \n
    incr row

    # Show the results of the 4 orientations of the grille cover.
    foreach {ptblock1 ptblock2 ptblock3 ptblock4} $ptblock {}

    regsub -all { } $ptblock1 . ptblock1
    regsub -all { } $ptblock2 . ptblock2
    regsub -all { } $ptblock3 . ptblock3
    regsub -all { } $ptblock4 . ptblock4
    while {[regexp $rowpattern $ptblock1]} {
	for {set i 1} {$i <= 4} {incr i} {
	    regexp $rowpattern [set ptblock$i] ptrow$i
	    regsub $rowpattern [set ptblock$i] {} ptblock$i
	    $t insert $row.end "    "
	    $t insert $row.end "[join [split [set ptrow$i] {}] { }]" \
		    grille_cover_$i
	}

	$t insert $row.end "\n"
	incr row
    }
    $t insert $row.end \n
    incr row

    $t insert $row.end "\n"
    incr row
    $t insert $row.end "\n"
    incr row

    $t configure -state disabled
}

proc clear_key_grille {args} {
    global cipherinfo

    $cipherinfo(object) undo

    display_cipher
}

proc do_sub_grille {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,pt) {}]} {
	error "Missing row for substitution"
    }
    if {[string match $cipherinfo(sub,ct) {}]} {
	error "Missing column for substitution"
    }
    if {[string match $cipherinfo(sub,offset) {}]} {
	set cipherinfo(sub,offset) 1
    }

    $cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,pt) \
	    $cipherinfo(sub,offset)

    display_pt
}

proc display_pt_grille {{ct {}}} {
    display_cipher_grille
}

proc display_key_grille {w args} {
    global cipherinfo

    $w configure -state normal

    set key [$cipherinfo(object) cget -key]
    set period [$cipherinfo(object) cget -period]

    $w delete 0.0 end

    $w insert 1.end \n
    $w insert 2.end \n
    set row 3
    set col 0

    set rowpattern [string repeat . $period]
    regsub -all 0 $key . key
    regsub -all 1 $key # key
    regsub -all {[234]} $key - key

    $w insert $row.end {  }
    for {set i 1} {$i <= $period} {incr i} {
	$w insert $row.end [format "%3d" $i]
    }
    $w insert $row.end \n
    incr row

    while {[regexp $rowpattern $key rowkey]} {
	regsub $rowpattern $key {} key
	$w insert $row.end "[format %2d [expr {$row-3}]]  [join [split $rowkey {}] {  }]\n"
	incr row
    }
    $w insert $row.end \n
    incr row

    $w configure -width [expr {$period * 3 + 10}] -height $row

    $w configure -state disabled
}

proc locate_best_tip_grille {} {
    global cipherinfo

    $cipherinfo(object) locate $cipherinfo(sub,pt)

    display_pt
    display_key
}

proc create_input_grille {w {bbar {}}} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w

	#
	# The Row input area
	#
	frame	$w.row
	label	$w.row.label1 -text "Row:"
	entry	$w.row.entry1 -width 10 -textvariable cipherinfo(sub,ct)
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
	pack	$w.row.label1 -side left -fill x
	pack	$w.row.entry1 -side left -fill x
	pack	$w.row -side top -fill x

	#
	# The Column input area
	#
	frame	$w.column
	label	$w.column.label -text "Column:"
	entry	$w.column.entry -width 10 -textvariable cipherinfo(sub,pt)
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


	$w.column.label configure -width 8
	$w.row.label1 configure -width 8
    }
}

proc solve_cipher_grille {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc save_cipher_grille {chanid} {
    global cipherinfo
}

proc set_bindings_grille {wid} {
    global cipherinfo

    set cipherinfo(sub,offset) 1
    $wid tag configure grille_hole_1 -foreground red
    $wid tag configure grille_hole_2 -foreground grey
    $wid tag configure grille_hole_3 -foreground grey
    $wid tag configure grille_hole_4 -foreground grey

    $wid tag configure grille_cover_1 -background grey
    $wid tag configure grille_cover_2 -background white
    $wid tag configure grille_cover_3 -background white
    $wid tag configure grille_cover_4 -background white

    # Binding for performing substitutions on the ciphertext grid.
    $wid tag bind grille_ctgrid <Button-1> {
	set tagList [%W tag names @%x,%y]
	set row {}
	set col {}
	foreach tag $tagList {
	    if {[regexp {^pos=([0-9]+),([0-9]+)} $tag null row col]} {
	    }
	}
	set cipherinfo(sub,ct) $row
	set cipherinfo(sub,pt) $col
	do_sub_grille
    }

    # Bindings for selecting which orientation of the grille cover
    # should be displayed.
    $wid tag bind grille_cover_1 <Button-1> {
	%W tag configure grille_cover_1 -background grey
	%W tag configure grille_cover_2 -background white
	%W tag configure grille_cover_3 -background white
	%W tag configure grille_cover_4 -background white
	%W tag configure grille_hole_1 -foreground red
	%W tag configure grille_hole_2 -foreground grey
	%W tag configure grille_hole_3 -foreground grey
	%W tag configure grille_hole_4 -foreground grey
	set cipherinfo(sub,offset) 1
    }
    $wid tag bind grille_cover_2 <Button-1> {
	%W tag configure grille_cover_1 -background white
	%W tag configure grille_cover_2 -background grey
	%W tag configure grille_cover_3 -background white
	%W tag configure grille_cover_4 -background white
	%W tag configure grille_hole_1 -foreground grey
	%W tag configure grille_hole_2 -foreground red
	%W tag configure grille_hole_3 -foreground grey
	%W tag configure grille_hole_4 -foreground grey
	set cipherinfo(sub,offset) 2
    }
    $wid tag bind grille_cover_3 <Button-1> {
	%W tag configure grille_cover_1 -background white
	%W tag configure grille_cover_2 -background white
	%W tag configure grille_cover_3 -background grey
	%W tag configure grille_cover_4 -background white
	%W tag configure grille_hole_1 -foreground grey
	%W tag configure grille_hole_2 -foreground grey
	%W tag configure grille_hole_3 -foreground red
	%W tag configure grille_hole_4 -foreground grey
	set cipherinfo(sub,offset) 3
    }
    $wid tag bind grille_cover_4 <Button-1> {
	%W tag configure grille_cover_1 -background white
	%W tag configure grille_cover_2 -background white
	%W tag configure grille_cover_3 -background white
	%W tag configure grille_cover_4 -background grey
	%W tag configure grille_hole_1 -foreground grey
	%W tag configure grille_hole_2 -foreground grey
	%W tag configure grille_hole_3 -foreground grey
	%W tag configure grille_hole_4 -foreground red
	set cipherinfo(sub,offset) 4
    }
}

proc remove_bindings_grille {wid} {
}
