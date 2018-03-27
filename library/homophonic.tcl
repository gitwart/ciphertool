# homophonic.tcl --
#
#	Display routines for the homophonic cipher type.
#
# RCS: @(#) $Id: homophonic.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
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

proc display_cipher_homophonic {args} {
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

    set exp ..
    while {[regexp ($exp) $ctext null word]} {
	regsub $exp $ctext {} ctext
	if {[string length $word] + $col > [expr {[$t cget -width] -5}]} {
	    $t insert [expr {$row+1}].end "\n"
	    $t insert [expr {$row+2}].end "\n"
	    $t insert [expr {$row+3}].end "\n"
	    set col 0
	    incr row 3
	}
#	puts "adding $word to display at ($col, $row)"

	foreach {s e} [split $word {}] {
	    ;#
	    ;# Clear the plaintext
	    ;#

	    set cttag $word
	    set cttag [string trimleft $cttag 0]
	    if {$cttag == ""} { set cttag 100 }

	    $t insert [expr {$row-1}].$col { }
	    $t insert [expr {$row-1}].[expr {$col+1}] { } "pt $cttag pt.$cttag"
	    $t insert [expr {$row-1}].[expr {$col+2}] { }

	    $t insert [expr {$row}].$col $s "ct"
	    $t insert [expr {$row}].[expr {$col+1}] $e "ct $cttag ct.$cttag"

	    $t tag add ct.$el $row.[expr {$col+1}]
	    $t tag add $el $row.[expr {$col+1}]
	    $t tag add ct.$word $row.[expr {$col+1}]

	    $t insert $row.[expr {$col+2}] { }

	    incr col 3
	}
	incr col
    }

    $t configure -state disabled
}

proc clear_key_homophonic {args} {
    global cipherinfo

    eval $cipherinfo(object) undo "01265176"

    display_cipher
}

proc do_sub_homophonic {args} {
    global cipherinfo

    if {[string match $cipherinfo(sub,ct) {}]} {
	error "Missing ciphertext for substitution"
    }

    if {[string match $cipherinfo(sub,pt) {}]} {
	$cipherinfo(object) undo $cipherinfo(sub,ct)
    } else {
	if {[string length $cipherinfo(sub,ct)] == 1} {
	    set cipherinfo(sub,ct) "0$cipherinfo(sub,ct)"
	}
	$cipherinfo(object) sub $cipherinfo(sub,ct) $cipherinfo(sub,pt)
    }

    display_pt
}

proc display_pt_homophonic {{ct {}}} {
    global cipherinfo

    set key [$cipherinfo(object) cget -fullkey]
    set ct [lindex $key 0]
    set pt [lindex $key 1]

    for {set i 0} {$i < [llength $ct]} {incr i} {
	set alphabet([lindex $ct $i]) [lindex $pt $i]
    }

    #
    # Use ".t tag ranges tagName to locate the positions of the ct values
    #
    set t $cipherinfo(text)
    $t configure -state normal

#    parray alphabet

    foreach ct [array names alphabet] {
	set pt $alphabet($ct)
	set start 1.0
	while 1 {
	    set indices [$t tag nextrange pt.$ct $start]
	    if {"$indices" == ""} break
	    foreach {start end} $indices break
	    eval $t delete $start $end
	    $t insert $start $pt
	    $t tag add pt.$ct $start
	    $t tag add pt $start
	    $t tag add $ct $start
	    set start $start+1c
	}
    }

    $t configure -state disabled
}

proc display_key_homophonic {w args} {
    global cipherinfo

    set key [$cipherinfo(object) cget -fullkey]
    set ct [lindex $key 0]
    set pt [lindex $key 1]

    for {set i 0} {$i < 100} {incr i} {
	set p [lindex $pt $i]
	set c [lindex $ct $i]

	if {![info exists pttoct($p)]} {
	    set pttoct($p) $c
	} else {
	    lappend pttoct($p) $c
	}
    }
    catch {
	set temp { }
	unset pttoct($temp)
    }
#    parray pttoct

    $w configure -state normal

    $w configure -width 28 -height 7

    $w delete 0.0 end

    $w insert 1.end \n

    $w insert 2.end \n
    set alphabet "a b c d e f g h i k l m n o p q r s t u v w x y z"
    for {set i 0} {$i < 25} {incr i} {
	$w insert 2.[expr {$i*3}] "  [lindex [string toupper $alphabet] $i]"
	set pttocol([lindex $alphabet $i]) $i
    }
    $w insert 2.end \n

    for {set x 3} {$x < 7} {incr x} {
	$w insert $x.end \n
    }

    foreach pt [lsort [array names pttoct]] {
	array set used_rows {
	    0 0
	    1 0
	    2 0
	    3 0
	}
	foreach ct [lsort -integer $pttoct($pt)] {
	    set row [expr {($ct-1) / 25}]
	    set col $pttocol($pt)

	    set used_rows($row) 1

	    set col [expr {$col * 3}]
	    incr row 3

	    $w insert $row.$col [format %3s $ct]
	}
	foreach row [array names used_rows] {
	    if {!$used_rows($row)} {
		$w insert [expr {$row+3}].$col "   "
	    }
	}
    }

    $w configure -state disabled
}

proc create_input_homophonic {w args} {
    global cipherinfo

    if {![winfo exists $w]} {
	frame $w

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

	#
	# The Ciphertext input area
	#
	
	frame	$w.ct
	label	$w.ct.label -text "Ctext:"
	entry	$w.ct.entry -width 5 -textvariable cipherinfo(sub,ct)
	pack	$w.ct.label $w.ct.entry -side left
	pack	$w.ct -fill x

	bind	$w.ct.entry <Key-underscore> {
	    if {[catch {
		set cipherinfo(sub,ct) [expr ([string trimleft [%W get] 0] + 100 - 2) %% 100 + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.ct.entry <Key-minus> [bind $w.ct.entry <Key-underscore>]
	bind	$w.ct.entry <Key-equal> {
	    if {[catch {
		set cipherinfo(sub,ct) [expr ([string trimleft [%W get] 0]) %%\
		    100 + 1]
	    } errors]} {
		puts "errors = $errors"
	    }
	    break
	}
	bind	$w.ct.entry <Key-plus> [bind $w.ct.entry <Key-equal>]
	pack	$w.ct.label -side left -fill x
	pack	$w.ct.entry -side left -fill x
	pack	$w.ct -side top -fill x

	$w.ct.label configure -width 8
	$w.pt.label configure -width 8

	#
	# The Locate tip input area
	#
#	frame	$w.lframe
#	label	$w.lframe.ptlabel -text "Tip:"
#	entry	$w.lframe.pt -textvariable cipherinfo(sub,pt)
#	label	$w.lframe.ctlabel -text "Start at:"
#	entry	$w.lframe.ct -textvariable cipherinfo(sub,ct)
#	pack	$w.lframe.ptlabel $w.lframe.pt -side left
#	pack	$w.lframe.ctlabel $w.lframe.ct -side left
#	pack	$w.pt -side top -fill x
#	pack	$w.ct -side top -fill x
#	pack	$w.lframe -side top -fill x
    }
}

proc solve_cipher_homophonic {args} {
    global cipherinfo

    $cipherinfo(object) solve
}

proc save_cipher_homophonic {chanid} {
}
