#!/bin/sh
# \
exec tclsh "$0" ${1+"$@"}

# patternmatch --
#
#	Search through the dictionary looking for words that match
#	a particular pattern.
#
# RCS: @(#) $Id: patternmatch.tcl,v 1.2 2004/09/08 14:42:09 wart Exp $
#
# Copyright (C) 2000-2008  Mike Thomas <wart@kobold.org>
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
package require CipherUtil
package require Dictionary

# Command line processing

if {[llength $argv] != 1} {
    puts stderr "Usage:  $argv0 pattern"
    exit 1
}

set pattern [lindex $argv 0]

# Iterate over all possible keys

proc generateHeadlineList {pattern} {
    set inputPatternList [CipherUtil::wordToOrder $pattern]
    set alphabet [list a b c d e f g h i j k l m n o p q r s t u v w x y z]
    for {set i 1} {$i < [string length $pattern]} {incr i} {
	set newPattern {}
	foreach letter [split $pattern {}] {
	    set letterIndex [lsearch $alphabet $letter]
	    if {$letterIndex == [string length $pattern]-1}  {
		set nextLetter a
	    } else {
		set nextLetter [lindex $alphabet [expr {$letterIndex + 1}]]
	    }
	    append newPattern $nextLetter
	}
	lappend inputPatternList [CipherUtil::wordToOrder $newPattern]
	set pattern $newPattern
    }

    return $inputPatternList
}

#set inputPatternList [generateHeadlineList $pattern]
set inputPatternList [CipherUtil::wordToOrder $pattern true]

set keywordList [Dictionary::lookupByLength [string length $pattern]]

foreach inputPattern $inputPatternList {
    puts "Trying pattern $inputPattern..."
    foreach keyword $keywordList {
        set dictionaryPattern [CipherUtil::wordToOrder $keyword true]
        #set dictionaryPattern [CipherUtil::wordToOrder $keyword]
        #puts "$keyword -> $dictionaryPattern"

        if {[string match $dictionaryPattern $inputPattern]} {
            puts $keyword
        }
    }
}
