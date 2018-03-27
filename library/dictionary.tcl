# dictionary.tcl --
#
#	Library routines for manipulating dictionary word lists.
#
# RCS: @(#) $Id: dictionary.tcl,v 1.20 2008/03/31 19:24:36 wart Exp $
#
# Copyright (C) 2001-2003  Mike Thomas <wart@kobold.org>
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

package provide Dictionary 1.0

# This particular dictionary package assumes that all words are in
# files sorted by length.  Each file is named "lenxx", where xx is the length
# of the words in the file.

namespace eval Dictionary {
}

# Dictionary::lookupByPattern
#
#	Lookup all words that match a particular pattern.
#
# Arguments:
#
#	pattern		Pattern to match.  The pattern must be of
#			the form "abcbde".
#
# Result:
#	A potentially very long list of words all of the same length.

proc Dictionary::lookupByPattern {pattern} {
    foreach letter [split $pattern {}] {
	set fixedPatternArray($letter) {}
	set patternArray($letter) {}
    }

    set wordList {}

    foreach word [lookupByLength [string length $pattern]] {
	# Match against the desired pattern
	array set patternArray [array get fixedPatternArray]
	array unset wordArray
	
	set isValidWord 1

	foreach wordLetter [split $word {}] \
		patternLetter [split $pattern {}] {
	    if {$patternArray($patternLetter) != ""} {
		if {$patternArray($patternLetter) != $wordLetter} {
		    set isValidWord 0
		} else {
		    if {[info exists wordArray($wordLetter)] && $wordArray($wordLetter) != $patternLetter} {
			set isValidWord 0
		    }
		}

		set patternArray($patternLetter) $wordLetter
		set wordArray($wordLetter) $patternLetter
	    } else {
		if {[info exists wordArray($wordLetter)] && $wordArray($wordLetter) != $patternLetter} {
		    set isValidWord 0
		}
		set patternArray($patternLetter) $wordLetter
		set wordArray($wordLetter) $patternLetter
	    }
	}

	if {$isValidWord} {
	    lappend wordList $word
	}
    }

    return $wordList
}

# Dictionary::findWords
#
#	Insert spaces into a string of plaintext to delineate word boundaries.
#	Groups of numbers are treated as a single word.
#
# Arguments:
#
#	pt		The string of plaintext without spaces.
#	updateCallback	A command to run whenever another space is found.
#			One argument will be passed to the command:  the
#			plaintext with the latest set of spaces inserted.
#	solution	The best solution found so far.  This should not be
#			set by the caller.  It is used internally as the
#			procedure is called recursively.
#
# Result:
#	The plaintext with spaces inserted at likely word boundaries.  An
#	empty string will be returned if any word boundaries could not be found.

proc Dictionary::findWords {pt {updateCallback {}} {solution {"" 0}} {bestStartVar {}}} {
    createWordTree
    return [wordtree splitbest $pt]
    #set bestResult [_findWords $pt $updateCallback $solution $bestStartVar]

    #return [lindex $bestResult 0]
}

proc Dictionary::_findWords {pt {updateCallback {}} {solution {"" 0}} {bestStartVar {}}} {
    set solutionString [lindex $solution 0]
    set solutionValue [lindex $solution 1]
    if {$bestStartVar == ""} {
	array set bestVar {}
    } else {
	upvar $bestStartVar bestVar
    }

    set wordLengths [lsort -decreasing -integer [Dictionary::availableLengths]]
    set maxLength [lindex $wordLengths 0]

    # Don't bother going down this road again if we've been here before
    # and found the best solution from this position
    if {[info exists bestVar([string length $pt])]} {
        return $bestVar([string length $pt])
    }

    if {[string length $pt] == 0} {
	return [list {} 0]
    }

    if {[string length $pt] < $maxLength} {
	set maxLength [string length $pt]
    }

    set bestSolution ""
    set bestValue -1

    foreach length $wordLengths {
	set tempWord [string range $pt 0 [expr {$length - 1}]]
        set tempSolution $solutionString

        # Strip off groups of numbers.
	if {[Dictionary::isWord $tempWord] || [Dictionary::isNumber $tempWord]} {
            lappend tempSolution $tempWord
            if {$length > 2} {
                set tempSolutionValue [expr {$length * $length}]
            } else {
                set tempSolutionValue 0
            }
	    if {$updateCallback != ""} {
		$updateCallback \
		    "$tempSolution [string range $pt $length end]"
	    }

            # Check if this produces a better solution than the previous
            # ones tried.
	    foreach {nextSolution nextValue}  [_findWords [string range $pt $length end] $updateCallback [list $tempSolution [expr $tempSolutionValue + $solutionValue]] bestVar] {}
            if {[expr $tempSolutionValue + $nextValue] > $bestValue} {
                set bestValue [expr $tempSolutionValue + $nextValue]
                if {$nextSolution == ""} {
                    set bestSolution "$tempWord"
                } else {
                    set bestSolution "$tempWord $nextSolution"
                }
#puts "$bestSolution: $bestValue"
            }
#puts [list [expr $tempSolutionValue + $nextValue] $tempSolution]
	}
    }

    # Mark this start location as invalid so that we don't have to come back
    # and try it again.
    set bestVar([string length $pt]) [list $bestSolution $bestValue]

    return [list $bestSolution $bestValue]
}

# Dictionary::createWordTree
#
#	Initialize the wordtree from all dictionary words.
#
# Arguments:
#
#	None.
#
# Result:
#	The name of the command that can be used to access
#	the word tree.

proc Dictionary::createWordTree {{cmd wordtree}} {
    foreach length [availableLengths] {
	foreach word [lookupByLength $length] {
	    $cmd add $word
	}
    }

    return $cmd
}
