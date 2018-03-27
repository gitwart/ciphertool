# k3board.tcl --
#
#	Library routines for a GUI that will manipulate K3 alphabet
#	fragments.
#
# RCS: @(#) $Id: k3board.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
#
# Copyright (C) 2002  Mike Thomas <wart@kobold.org>
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

package require cipher

package provide K3Board 1.0

namespace eval K3Board {
    set viewWidget {}
    set manipWidget {}
}

# K3Board::loadFragments
#
#	Load k3 fragments from a filename that was provided by a UI filebrowser.
#
# Arguments:
#
#	file	The name of the file containing the saved aristocrat
#		or patristocrat cipher.
#	fragVar	The variable in the caller's scope in which the fragments
#		will be stored.
#
# Result:
#	A numeric string.

proc K3Board::loadFragments {file fragVar} {
    upvar $fragVar fragments
    variable viewWidget
    variable manipWidget

    if {[string match $file {}]} return

    set fragments [CipherUtil::loadK3Fragments $file]

    showFragments $fragments $viewWidget

    puts "fragments found:  $fragments"
}

# K3Board::showFragments
#
#	Display the current set of fragments in the UI.
#
# Arguments:
#
#	fragmentList	The list of fragments to display.
#	viewWidget	The text widget in which to display the fragments.
#
# Side Effects:
#
#	The contents of the viewWidget are discarded before displaying the
#	set of fragments.
#
# Result:
#	None.

proc K3Board::showFragments {fragmentList viewWidget} {
    $viewWidget delete 0.0 end

    set col 0
    set maxRows 4
    set colPadding 2

    for {set row 0} {$row < $maxRows} {incr row} {
	$viewWidget insert $row.end \n
    }

    while {[llength $fragmentList]} {
	puts "fragment index is [llength $fragmentList]"

	# The fragment index is simply a unique number for this fragment
	# among the entire set.
	set fragIndex [llength $fragmentList]

	# Find the max length of a fragment in this column.
	set maxFragLength 0
	for {set i 0} {$i < $maxRows} {incr i} {
	    set fragLength [string length [lindex $fragmentList $i]]
	    if {$fragLength > $maxFragLength} {
		set maxFragLength $fragLength
	    }
	}
	set colSize [expr {$maxFragLength + $colPadding}]

	for {set row 0} {$row < $maxRows} {incr row} {
	    set fragment \
		    [format %-${colSize}s [lindex $fragmentList $row]]
	    puts "$viewWidget insert $row.$col $fragment [list frag_$fragIndex]"
	    $viewWidget insert [expr {$row+1}].$col $fragment \
		    [list frag_$fragIndex]
	}

	set fragmentList [lrange $fragmentList $maxRows end]
	
	incr col $colSize
    }
}

# K3Board::setDragDropBindings
#
#	Initialize the bindings for dragging and droppping the alphabet
#	fragments.
#
# Arguments:
#
#	viewWidget	The text widget in which to display the fragments.
#	manipWidget	The text widget in which the fragments will be
#			manipulated.
#
# Result:
#	None.

#TODO:  Modify from the current columnar bindings.
proc K3Board::setDragDropBindings {viewWidget manipWidget} {
    $wid tag configure frag_selected -background yellow

    # Tag for selecing a column to drag.
    $wid tag bind fragment <ButtonPress-1> {
	set tagList [%W tag names @%x,%y]
	set fragId {}
	foreach tag $tagList {
	    if {[regexp {^frag_([0-9]+)} $tag null fragId]} {
	    }
	}
	%W tag remove frag_selected 0.0 end
	foreach {start end} [%W tag ranges frag_$fragId] {
	    %W tag add frag_selected $start
	}
	break
    }

    # Tag for dragging a fragment
    $wid tag bind fragment <B1-Motion> {
    }

    # Tag for dropping a column to a new position
    $wid tag bind fragment <ButtonRelease-1> {
	%W tag remove frag_selected 0.0 end
	break
    }

    # Don't update the X selection while we're dragging a column around.
    bind $wid <B1-Motion> {
	if {[llength [%W tag ranges frag_selected]] > 0} {
	    break
	}
    }
}
