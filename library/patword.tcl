# patword.tcl --
#
#	Library routines for patristocrat brute force word searching.
#
# RCS: @(#) $Id: patword.tcl,v 1.8 2004/09/08 17:05:00 wart Exp $
#
# Copyright (C) 2003  Mike Thomas <wart@kobold.org>
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
package require Dictionary

package provide PatWord 1.0

namespace eval Patword {
    variable count 0
    variable stepInterval
    variable maxKey
    variable maxValue
    variable maxEndPos
    variable maxDepth 0
    variable exitAfterStartWordFound 0

    variable checkpoint {}

    variable updateScript Patword::showIter
    variable bestScript Patword::showBest

    namespace eval KeysVisited {
    }
}

proc Patword::showIter {cipherObj count result word wordList} {
    puts "# [concat $result $word]"
    puts "# $count: [$cipherObj cget -pt]"
    puts ""

    return -1
}

proc Patword::showBest {cipherObj count result word wordList} {
    puts "# ([$cipherObj cget -key])"
    puts "# [concat $result $word]"
    puts "# Fit: [score value [$cipherObj cget -pt]]"
    puts "# $count: [$cipherObj cget -pt]"
    puts ""
}

proc Patword::fit {cipherObj startPos result {startWordList {}}} {
    variable count
    variable stepInterval
    variable maxKey
    variable maxValue
    variable maxEndPos
    variable updateScript
    variable bestScript
    variable maxDepth
    variable exitAfterStartWordFound
    variable checkpoint

    set usingStartWord [llength $startWordList]

    set origKey [$cipherObj cget -key]
    if {! $usingStartWord && [info exists KeysVisited::${startPos}($origKey)]} {
#	puts "# ($level) Duplicate key:  $startPos,[lindex [$cipherObj cget -key] 1]"
	#puts "# Already visited key '$origKey'"
	#puts "# $result"
	#puts ""
	return 0
    }

    set level [llength $result]
    if {($maxDepth > 0) && ($level >= $maxDepth)} {
	return 0
    }

    set ctLength [$cipherObj cget -length]
    if {$startPos >= $ctLength} {
	return 0
    }

    set startWordFound 1
    if {$usingStartWord} {
	set startWord [lindex $startWordList 0]
	set startWordList [lrange $startWordList 1 end]
	set startWordFound 0
    }

    set KeysVisited::${startPos}($origKey) 1
    # Any keys that were attempted later on are likely not going to help us
    # anymore.  20 characters feels like a decent limit.
    array unset KeysVisited::[expr {$startPos + 17}]
    array unset KeysVisited::[expr {$startPos + 18}]
    array unset KeysVisited::[expr {$startPos + 19}]

    set ptPattern [string map {{ } ?} [string range [$cipherObj cget -pt] $startPos end]]
    if {$usingStartWord && $exitAfterStartWordFound} {
	set wordList $startWord
    } else {
	set wordList [Dictionary::allWordsMatching $ptPattern]
    }

    foreach rawWord $wordList {
	incr count

	# Strip off any punctuation
	set word [string map {- {} ' {}} $rawWord]
	set length [string length $word]
	if {$length == 0} {
	    continue
	}

	set endPos [expr {$startPos + $length - 1}]
	set ct [string range [$cipherObj cget -ct] $startPos $endPos]

	# Run along until we find uor starting word.  Usually this
	# won't happen and we'll just accept the current word.
	if {$usingStartWord} {
	    if {! $startWordFound && $startWord != $rawWord} {
		continue
	    } else {
		set startWordFound 1
#		if {! $exitAfterStartWordFound} {
#		    set usingStartWord 0
#		}
	    }
	}

	# If the word fits at this position then try to find
	# additional words that matches at the next position.
	if {! [catch {$cipherObj substitute $ct $word}]} {
	    # Check if this beats any previous best end position and
	    # print the result if so.
	    if {$endPos > $maxEndPos || $endPos == [$cipherObj cget -length]-1} {
		set maxKey [$cipherObj cget -key]
		set maxEndPos $endPos
		if {$bestScript != ""} {
		    $bestScript $cipherObj $count $result $rawWord $wordList
		}
	    }

	    if {$updateScript != ""} {
		set skipToLevel [$updateScript $cipherObj $count $result $rawWord $wordList]
		if {$skipToLevel == "restart"} {
		    array unset KeysVisited::${startPos}($origKey)
		    set checkpoint [concat $result $rawWord]
		    return [llength $result]
		}
		if {$skipToLevel != -1 && [llength $result] > $skipToLevel} {
		    # The result is actually 1 larger than the level
		    # number,
		    $cipherObj undo
		    $cipherObj restore [lindex $origKey 0] [lindex $origKey 1]
		    return [expr {[llength $result] - 1 - $skipToLevel}]
		}
	    }

	    # If we're at the end of the cipher, don't bother going on.

	    # Check for illegal trigrams.  This should help prune the
	    # search space much earlier.
	    if {! [Dictionary::containsIllegalTrigram \
		    [string range \
			    [$cipherObj cget -pt] \
			    [expr {$endPos+1}] \
			    end]]} {

		set levelsToSkip [fit $cipherObj [expr {$endPos + 1}] \
			[concat $result $rawWord] \
			$startWordList]

		# There's only one possible start word, so clear the
		# start word list after it's been found and we've passed
		# the data on.
		set startWordList {}

		if {$levelsToSkip > 0} {
#			puts "# ($level) Found $levelsToSkip levels to skip"
		    $cipherObj undo
		    $cipherObj restore [lindex $origKey 0] [lindex $origKey 1]
		    incr levelsToSkip -1
		    return $levelsToSkip
		}
	    }

	    $cipherObj undo
	    $cipherObj restore [lindex $origKey 0] [lindex $origKey 1]
	}
    }

    set wordList {}

    return 0
}
