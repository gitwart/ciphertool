# hillclimb.tcl --
#
#	Library routines for performing a hilll climbing search.
#
# RCS: @(#) $Id: hillclimb.tcl,v 1.17 2008/03/17 00:02:24 wart Exp $
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

package require cipher
package provide Hillclimb 1.0

namespace eval Hillclimb {
    variable neighborProc swapGenericKey
    variable valueProc {}
    variable decipherProc {}
    variable stepInterval 2000
    variable stepCommand [namespace current]::showFit
    variable bestFitCommand [namespace current]::showFit
    variable keycipher {}
    variable registerProc [namespace current]::registerMaxKey
    variable mutationRequested 0
    variable mutationAmount 0
    variable scoreObj score
    variable coarseScoreObj score
    variable fineScoreObj score

    variable cipherObject {}
}

# Hillclimb::mutate
#
#	Mutate the current key by wandering some number of steps away
#	by traveling to neighbor keys.
#
# Arguments:
#
#	fullKey		Initial key to be mutated.
#	amount		Amount of mutation to apply.
#	type		Optional.  Treat the key as belonging to a cipher
#			of this type.  If not supplied, the previously
#			selected neighbor key procedure will be used.
#
# Result:
#	A new full key.

proc Hillclimb::mutate {fullKey amount {type {}}} {
    variable neighborProc
    variable swapKeyProc
    variable fixedKeyPositions

    set localNeighborProc $neighborProc
    if {$type != {}} {
	set localNeighborProc $swapKeyProc($type)
    }
    set mutantKey $fullKey

    for {set i 0} {$i < $amount} {incr i} {
	set neighborList [$localNeighborProc $mutantKey $fixedKeyPositions]
	set mutantKey [lindex $neighborList [expr {int(rand() * [llength $neighborList])}]]
    }

    return $mutantKey
}

# Hillclimb::scoreKey
#
#       Calculate the score value of a key, using the current cipher
#       object.
#
# Arguments:
#
#	key		The key to score against the current cipher.
#
# Result:
#	A score value.

proc Hillclimb::scoreKey {key} {
    variable scoreObj
    variable decipherProc
    variable cipherObject

    return [$scoreObj value [$decipherProc $cipherObject $key]]
}

# Hillclimb::generateInsertNeighborKeys
#
#	This routine generates a list of neighboring keys by swapping
#	pairs of letters.
#
# Arguments:
#
#	keyword
#	unusedList
#
# Result:
#	A list of keys.

proc Hillclimb::generateInsertNeighborKeys  {keyword {unusedList}} {
    # Make a list of the letters that don't appear in the keyword
    set unusedLetters $unusedList
    if {[llength $unusedList] == 0} {
	foreach letter {a b c d e f g h i j k l m n o p q r s t u v w x y z} {
	    if {[string first $letter $keyword] == -1} {
		lappend unusedList $letter
	    }
	}
    }

    set keyLength [string length $keyword]
    set keyList {}
    foreach letter $unusedList {
	lappend tempKeyList $letter$keyword

	for {set i 0} {$i < [expr {$keyLength-1}]} {incr i} {
	    lappend tempKeyList [string range $keyword 0 $i]$letter[string range $keyword [expr {$i + 1}] end]
	}
	lappend tempKeyList [string range $keyword 0 $i]$letter[string range $keyword [expr {$i + 1}] end]
    }

    set keyList $tempKeyList

    return $keyList
}

# Hillclimb::plugKeyHoles
#
#
# Arguments:
#
#	key	The partial key.
#
# Result:
#	A list with two elements.  The first is the key string with the holes
#	filled in with the unused letters.  The second is a string that
#	contains 1's where there were characters in the input key, and 0's
#	where there were spaces.
#

proc Hillclimb::plugKeyHoles {key} {
    #puts -->[info level 0]
    set holeString $key
    regsub -all {[a-z0-9#]} $holeString 1 holeString
    regsub -all { } $holeString 0 holeString

    # TODO:  There's got to be a less hackish way of determining the
    # set of valid key values in these next few lines.  We should really
    # be getting the cipher type and querying it for the set of valid
    # characters.
    set alphabet {a b c d e f g h i j k l m n o p q r s t u v w x y z}
    if {[string length $key] == 25} {
	set alphabet {a b c d e f g h i k l m n o p q r s t u v w x y z}
    }

    if {[string length $key] == 27} {
	set alphabet {a b c d e f g h i j k l m n o p q r s t u v w x y z #}
    }

    if {[string length $key] == 36} {
	set alphabet {a 1 b 2 c 3 d 4 e 5 f 6 g 7 h 8 i 9 j 0 k l m n o p q r s t u v w x y z}
    }


    foreach letter $alphabet {
	if {[set index [string first $letter $key]] == -1} {
	    set holeIndex [string first { } $key]
	    if {$holeIndex != -1} {
		set key [string replace $key $holeIndex $holeIndex $letter]
	    } else {
		# Uh oh!  Someone passed us a bad key!
		error "Invalid key.  Check for duplicate letters:  $key (length = [string length $key])"
	    }
	}
    }

    #puts "  returning $key ([string length $key]) $holeString ([string length $holeString])"
    return [list $key $holeString]
}

# Hillclimb::showFit
#
#	Display information about a key.  This routine is normally used to
#	provide feedback to the user about progress made so far.
#
# Arguments:
#
#	key	The key that produced the fit
#	step	The total number of keys tried so far.
#	value	The value of the fit.
#
# Result:
#	None.

proc Hillclimb::showFit {key step {value ""} {keyword ""}} {
    variable decipherProc
    variable cipherObject

    puts -nonewline "#$key"

    if {$keyword != ""} {
	puts -nonewline " ($keyword)"
    }

    if {$value != ""} {
	puts "\tFit:  $value"
    } else {
	puts ""
    }

    puts "#$step: [$decipherProc $cipherObject $key]"
    puts ""
}

# Hillclimb::registerMaxKey
#
#	Display information about a potential max key to the user.
#
# Arguments:
#
#	key	The initial key for hill climbing.
#
# Result:
#	A list of two elements.  The first element is the key that
#	generated the best value, the second is the value.

proc Hillclimb::registerMaxKey {key pt value limitvalue depth count} {
    puts "$depth ($count):\t$value ($limitvalue)\t$key $pt"
}

# Hillclimb::recstart
#
#	This routine starts the recursive hill climb.
#
# Arguments:
#
#	key	The initial key for hill climbing.
#
# Result:
#	A list of two elements.  The first element is the key that
#	generated the best value, the second is the value.

proc Hillclimb::recstart {key keyvalue depth} {
    #puts -->[info level 0]
    variable decipherProc
    variable neighborProc
    variable stepInterval
    variable stepCommand
    variable bestFitCommand
    variable keycipher
    variable registerProc
    variable mutationRequested
    variable mutationAmount
    variable cipherObject
    variable scoreObj
    variable fixedKeyPositions

    set maxValue $keyvalue
    set localMaxValue $maxValue
    #puts -->[info level 0]\t$localMaxValue
    set maxKey $key
    set curIteration 0

    if {$mutationRequested} {
	return [list $key $keyvalue]
    }

    foreach neighborKey [$neighborProc $key $fixedKeyPositions] {
	incr curIteration
	set pt [$decipherProc $cipherObject $neighborKey]
	set value [$scoreObj value $pt]
	if {$value > $localMaxValue} {

	    foreach  {returnkey value} [Hillclimb::recstart $neighborKey \
		    $value [expr {$depth + 1}]] {}

	    #puts "\tReturned to level $depth"
	    if {$value > $maxValue} {
		#puts "Level $depth max is now $value ($curIteration)"
		$registerProc $returnkey [$decipherProc $cipherObject $returnkey] $value $localMaxValue $depth $curIteration

		set maxValue $value
		set maxKey $returnkey
	    }

	    if {$bestFitCommand != ""} {
		$bestFitCommand $neighborKey $curIteration $value
	    }
	}

	if {$stepInterval && $curIteration % $stepInterval == 0} {
	    if {$stepCommand != ""} {
		$stepCommand $neighborKey $curIteration
	    }
	}
    }

    if {$maxValue > $localMaxValue} {
	return [list $maxKey $maxValue]
    } else {
	return [list $maxKey $localMaxValue]
    }
}

# Hillclimb::start
#
#	This routine starts climbing a single hill starting from a fixed
#	position.
#
# Arguments:
#
#	key	The initial key for hill climbing.
#
# Result:
#	A list of two elements.  The first element is the key that
#	generated the best value, the second is the value.

proc Hillclimb::start {key} {
    variable decipherProc
    variable neighborProc
    variable stepInterval
    variable stepCommand
    variable bestFitCommand
    variable cipherObject
    variable scoreObj
    variable fineScoreObj
    variable fixedKeyPositions

#    set bestFitCommand [namespace current]::showFit

#    puts "Starting hill climb with [$scoreObj type] scoring function"

    set maxValue [$scoreObj value [$decipherProc $cipherObject $key]]
    set maxKey $key
    set maximaFound 0
    set curIteration 0

    if {$bestFitCommand != ""} {
	$bestFitCommand $key $curIteration $maxValue
    }

    while {! $maximaFound} {
	set maximaFound 1
	set curKey $maxKey

	foreach neighborKey [Hillclimb::randomizeList [$neighborProc $curKey $fixedKeyPositions]] {
	    incr curIteration

	    set value [$scoreObj value \
		    [$decipherProc $cipherObject $neighborKey]]
	    if {$value > $maxValue} {
		set maximaFound 0
		set maxValue $value
		set maxKey $neighborKey

		if {$bestFitCommand != ""} {
		    $bestFitCommand $neighborKey $curIteration $value
		}
	    }

	    if {$stepInterval && $curIteration % $stepInterval == 0} {
		if {$stepCommand != ""} {
		    $stepCommand $neighborKey $curIteration
		}
	    }
	}
#        showFit $neighborKey $curIteration $value

        # A coarse-grained scoring function finds the approximate
        # location of the hilltop.  The fine-grained scoring function
        # is better suited to find the actual hilltop.
#        if {$maximaFound} {
#            if {$scoreObj != $fineScoreObj} {
#                puts "coarse hilltop found using [$scoreObj type] scoring function.  Switching to fine [$fineScoreObj type] scoring function"
#                set scoreObj $fineScoreObj
#                set maximaFound 0
#                set value [$scoreObj value \
#                        [$decipherProc $cipherObject $maxKey]]
#                set maxValue $value
#                set stepInterval 1
#set stepCommand [namespace current]::showFit
#            }
#        }
#    }

    return [list $maxKey $maxValue]
}

# Hillclimb::patTipSearch
#
#	This routine performs a hillclimb on a patristocrat cipher with
#	a tip, with or without a location for the tip.
#
# Arguments:
#
#	numHills The number of hills to climb for each possible tip
#		location.
#	tip	The known tip
#	tipLocation	The numerical index of the start of the tip.  If
#		not specified then every valid tip location is used.
#
# Result:
#	A list of two elements.  The first element is the key that
#	generated the best value, the second is the value.

proc Hillclimb::patTipSearch {numHills tip {tipLocation -1}} {
    #puts -->[info level 0]
    variable stepCommand
    variable bestFitCommand
    variable cipherObject
    variable fixedKeyPositions
    variable mutationAmount
    variable decipherProc

    set count 0

    # Turn off the progress updates for the nested Hilllclimb::start calls.
    # We only want to see the updates for the entire set.
    set localStepCommand $stepCommand
    set localBestFitCommand $bestFitCommand

    set stepCommand {}
    set bestFitCommand {}

    set maxValue 0
    set maxHillKey {}

    if {$tipLocation != -1} {
	set knownTipLocation 1
    } else {
	set knownTipLocation 0
	set tipLocation 0
    }

    # This loop will find every possible valid tip location.  It will end
    # when no more valid tip locations are found.  This is indicated by
    # the "aristocrat locate tip" method throwing an exception.
    $cipherObject undo abcdefghijklmnopqrstuvwxyz
    while {! [catch {set tipCt [$cipherObject locate $tip $tipLocation]} msg]} {
	set tipStartIndex [expr $tipLocation + [string first $tipCt [string range [$cipherObject cget -ct] $tipLocation end]]]
	if {[string length $tipCt] < [string length $tip]} {
            #puts "#Tip fell off the end of the cipher."
	    break
	}
	if {$knownTipLocation && $tipStartIndex != $tipLocation} {
	    #puts "#Tip did not fit at the required location ($tipStartIndex != $tipLocation)"
	    break
	}
	if {$tipCt == "" && $tip != ""} {
	    #puts "Tip $tip not found in ct [$cipherObject cget -ct]"
	    break
	}

	#puts "Tip found at $tipCt ($tipStartIndex).  Produces key [$cipherObject cget -key]"
	set tipLocation $tipStartIndex

	foreach {newkey holes} \
		[Hillclimb::plugKeyHoles [lindex [$cipherObject cget -key] 1]] {}
	set Hillclimb::fixedKeyPositions $holes
	set hillKey [list [lindex [$cipherObject cget -key] 0] $newkey]
	#puts "Using key $hillKey"

	# Climb the hill for a while
	for {set iter 0} {$iter < $numHills} {incr iter} {

	    foreach {bestKey value} [Hillclimb::start $hillKey] {}

	    if {$value > $maxValue} {
		set maxValue $value
		set maxHillKey $bestKey
		if {$localBestFitCommand != ""} {
		    $localBestFitCommand $maxHillKey $iter $value
		}
	    }

	    incr count

	    set hillKey [::Hillclimb::mutate $bestKey $mutationAmount]
	}

	if {$localBestFitCommand != ""} {
	    $localBestFitCommand $hillKey $count
	}

	# Don't loop if the tip location is known to be true.
	if {$knownTipLocation || $tip == ""} {
	    break
	}
	incr tipLocation
	$cipherObject undo abcdefghijklmnopqrstuvwxyz
    }

    if {$maxHillKey != ""} {
	$decipherProc $cipherObject $maxHillKey
    }

    set stepCommand $localStepCommand
    set bestFitCommand $localBestFitCommand

    return [list $maxHillKey $maxValue]
}
