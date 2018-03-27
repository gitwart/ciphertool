# ctool_inputs.tcl --
#
#	A collection of procedures for generating input widgets for
#	the various cipher types.
#
# RCS: @(#) $Id: ctool_inputs.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
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

proc create_radio_buttons {w var {list {}}} {
    array set alphabet {
	0 a 1 b 2 c 3 d 4 e 5 f 6 g 7 h 8 i 9 j 10 k 11 l 12 m 13 n 14 o 15 p
	16 q 17 r 18 s 19 t 20 u 21 v 22 w 23 x 24 y 25 z}
    foreach el [array names alphabet] { set alphabet($alphabet($el)) $el }

    frame $w

    if {[string match $list a-z]} {
	for {set i 0} {$i < 26} {incr i} {
	    lappend tlist $alphabet($i)
	}
	set list $tlist
    } elseif {[string match $list 0-9]} {
	for {set i 0} {$i < 10} {incr i} {
	    lappend tlist $i
	}
	set list $tlist
    } elseif {[string match $list 1-9]} {
	for {set i 1} {$i < 10} {incr i} {
	    lappend tlist $i
	}
	set list $tlist
    }

    set index 0
    foreach el $list {
	radiobutton $w.$index -text $el\
	    -highlightthickness 0\
	    -padx 3 -pady 1\
	    -value $el\
	    -variable $var\
	    -takefocus 0\
	    -selectcolor green\
	    -activebackground #ffbbff\
	    -indicatoron 0\
	    -font "-adobe-courier-bold-r-normal--14-140-75-75-m-90-iso8859-1"
	pack $w.$index -side left -anchor w
	incr index
    }
}
