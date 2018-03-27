# hillclimbCiphers.tcl --
#
#	Cipher type-specific routines for performing a hilll climbing search.
#
# RCS: @(#) $Id: hillclimbCiphers.tcl,v 1.14 2008/03/31 20:07:02 wart Exp $
#
# Copyright (C) 2001-2008  Mike Thomas <wart@kobold.org>
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
    # Procedures for deciphering ciphers from a key.
    variable decipherProc
    set decipherProcFromType(aristocrat)	Hillclimb::decipherAristocrat
    set decipherProcFromType(bigbifid)	Hillclimb::decipherSimple
    set decipherProcFromType(bifid)	Hillclimb::decipherSimple
    set decipherProcFromType(digrafid)	Hillclimb::decipherAristocrat
    set decipherProcFromType(fmorse)	Hillclimb::decipherSimple
    set decipherProcFromType(foursquare)	Hillclimb::decipherAristocrat
    set decipherProcFromType(gromark)	Hillclimb::decipherGromark
    set decipherProcFromType(phillips)	Hillclimb::decipherSimple
    set decipherProcFromType(playfair)	Hillclimb::decipherSimple
    set decipherProcFromType(bigplayfair)	Hillclimb::decipherSimple
    set decipherProcFromType(ragbaby)	Hillclimb::decipherSimple
    set decipherProcFromType(trifid)	Hillclimb::decipherSimple
    set decipherProcFromType(twosquare)	Hillclimb::decipherAristocrat

    # Procedures for generating a list of keys from a keyword.
    variable fullKeyList
    set fullKeyListFromType(aristocrat)	Hillclimb::getAristocratFullKeyList
    set fullKeyListFromType(bigbifid)	Hillclimb::get6x6KeysquareFullKeyList
    set fullKeyListFromType(bifid)	Hillclimb::getKeysquareFullKeyList
    set fullKeyListFromType(digrafid)	Hillclimb::getDigrafidFullKeyList
    set fullKeyListFromType(fmorse)	Hillclimb::getK1FullKeyList
    set fullKeyListFromType(foursquare)	Hillclimb::getTwosquareFullKeyList
    set fullKeyListFromType(gromark)	Hillclimb::getK1FullKeyList
    set fullKeyListFromType(phillips)	Hillclimb::getKeysquareFullKeyList
    set fullKeyListFromType(playfair)	Hillclimb::getKeysquareFullKeyList
    set fullKeyListFromType(bigplayfair) Hillclimb::get6x6KeysquareFullKeyList
    set fullKeyListFromType(ragbaby)	Hillclimb::getRagbabyFullKeyList
    set fullKeyListFromType(trifid)	Hillclimb::getTrifidFullKeyList
    set fullKeyListFromType(twosquare)	Hillclimb::getTwosquareFullKeyList

    # Procedures for generating a list of keys from a keyword.
    variable generateChurnKeyProc
    set generateChurnKeyList(aristocrat) Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(bigbifid)	Hillclimb::generateUnsupportedChurnKeylist
    set generateChurnKeyList(bifid)	Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(digrafid)	Hillclimb::generateUnsupportedChurnKeylist
    set generateChurnKeyList(fmorse)	Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(foursquare) Hillclimb::generateUnsupportedChurnKeylist
    set generateChurnKeyList(gromark)	Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(phillips)	Hillclimb::generatePhillipsChurnKeylist
    set generateChurnKeyList(playfair)	Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(bigplayfair) Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(ragbaby)	Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(trifid)	Hillclimb::generateSimpleChurnKeylist
    set generateChurnKeyList(twosquare)	Hillclimb::generateUnsupportedChurnKeylist

    # Procedures for generating neighbor keys using the swap method.
    # Each cipher needs its own swap procedure to handle its
    # specific key structure.
    variable swapKeyProc
    set swapKeyProc(aristocrat)	Hillclimb::swapAristocratKey
    set swapKeyProc(bigbifid)	Hillclimb::swapGenericKey
    set swapKeyProc(bifid)	Hillclimb::swapGenericKey
    set swapKeyProc(digrafid)	Hillclimb::swapTwosquareKey
    set swapKeyProc(fmorse)	Hillclimb::swapGenericKey
    set swapKeyProc(foursquare)	Hillclimb::swapTwosquareKey
    set swapKeyProc(gromark)	Hillclimb::swapGenericKey
    set swapKeyProc(phillips)	Hillclimb::swapKeysquareKey
    set swapKeyProc(playfair)	Hillclimb::swapGenericKey
    set swapKeyProc(bigplayfair) Hillclimb::swapGenericKey
    set swapKeyProc(ragbaby)	Hillclimb::swapGenericKey
    set swapKeyProc(trifid)	Hillclimb::swapGenericKey
    set swapKeyProc(twosquare)	Hillclimb::swapTwosquareKey

    # Procedures for mating two keys with one crossover point.
    # Each cipher needs its own mate procedure to handle its
    # specific key structure.
    variable mateProc
    set mateProcFromType(aristocrat)	Hillclimb::mateAristocratKeys
    set mateProcFromType(bifid)         Hillclimb::mateGenericKeys2

    # Generate a single unkeyed alphabet for the cipher.  This is often used
    # as a seed for hillclimbing.
    variable singleSeedKey
    set singleSeedKey(aristocrat)	abcdefghijklmnopqrstuvwxyz
    set singleSeedKey(bifid)		abcdefghiklmnopqrstuvwxyz
    set singleSeedKey(bigbifid)		a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz
    set singleSeedKey(trifid)		abcdefghijklmnopqrstuvwxyz#
    set singleSeedKey(fmorse)		$singleSeedKey(aristocrat)
    set singleSeedKey(foursquare)	[list $singleSeedKey(bifid) \
	    $singleSeedKey(bifid)]
    set singleSeedKey(gromark)		$singleSeedKey(aristocrat)
    set singleSeedKey(phillips)		$singleSeedKey(bifid)
    set singleSeedKey(playfair)		$singleSeedKey(bifid)
    set singleSeedKey(bigplayfair)	$singleSeedKey(bigbifid)
    set singleSeedKey(ragbaby)		abcdefghiklmnopqrstuvwyz
    set singleSeedKey(digrafid)		[list $singleSeedKey(trifid) \
	    $singleSeedKey(trifid)]
    set singleSeedKey(twosquare)	$singleSeedKey(foursquare)

    # Optional list of strings describing which key positions are fixed.
    variable fixedKeyPositions {}
}

# Hillclimb::decipherSimple
#
#	Get the plaintext for a cipher.  Most cipher type will use this
#	routine.
#
# Arguments:
#
#	cipherobj	Cipher object of the appropriate type.
#	key		Key to use for retrieving plaintext.
#
# Result:
#	A string of plaintext.

proc Hillclimb::decipherSimple {cipherobj key} {
    $cipherobj restore $key

    return [$cipherobj cget -pt]
}

# Hillclimb::decipherAristocrat
#
#	Get the plaintext for an aristocrat cipher.  Since the key structures
#	are the same for aristocrat and twosquare ciphers, this can be used
#	for both.
#
# Arguments:
#
#	cipherobj	Cipher object of the appropriate type.
#	key		Key to use for retrieving plaintext.
#
# Result:
#	A string of plaintext.

proc Hillclimb::decipherAristocrat {cipherobj key} {
    $cipherobj restore [lindex $key 0] [lindex $key 1]

    return [$cipherobj cget -pt]
}

# Hillclimb::decipherGromark
#
#	Get the plaintext for a gromark cipher.
#
# Arguments:
#
#	cipherobj	Cipher object of the appropriate type.
#	key		Key to use for retrieving plaintext.
#
# Result:
#	A string of plaintext.

proc Hillclimb::decipherGromark {cipherobj key} {
    $cipherobj restore $key abcdefghijklmnopqrstuvwxyz

    return [$cipherobj cget -pt]
}

# Hillclimb::getKeysquareFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getKeysquareFullKeyList {keyword} {
    set fullkey [key generate -k1 $keyword]
    regsub {j} $fullkey {} fullkey
    return $fullkey
}

# Hillclimb::get6x6KeysquareFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::get6x6KeysquareFullKeyList {keyword} {
    set fullkey [string map {a a1 b b2 c c3 d d4 e e5 f f6 g g7 h h8 i i9 j j0} [key generate -k1 $keyword]]
    return $fullkey
}

# Hillclimb::getTrifidFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getTrifidFullKeyList {keyword} {
    set fullKeyList {}
    set fullkey [key generate -k1 $keyword]
    lappend fullKeyList $fullkey#
    lappend fullKeyList #$fullkey

    # Generate a second key that has a # character between the
    # keyword and the rest of the alphabet.  This is a common
    # variation on the trifid key for more complex puzzles.

    set keyend [string trimleft $fullkey $keyword]
    set keystart [string trimright $fullkey $keyend]
    lappend fullKeyList $keystart#$keyend
    lappend fullKeyList $keyend#$keystart

    return $fullKeyList
}

# Hillclimb::getDigrafidFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getDigrafidFullKeyList {keyword} {
    set fullKeyList {}
    set fullkey [key generate -k1 $keyword]
    lappend fullKeyList [list abcdefghijklmnopqrstuvwxyz# $fullkey#]
    lappend fullKeyList [list $fullkey# abcdefghijklmnopqrstuvwxyz#]
    lappend fullKeyList [list abcdefghijklmnopqrstuvwxyz# #$fullkey]
    lappend fullKeyList [list #$fullkey abcdefghijklmnopqrstuvwxyz#]

    # Generate a second key that has a # character between the
    # keyword and the rest of the alphabet.  This is a common
    # variation on the trifid key for more complex puzzles.

    set keyend [string trimleft $fullkey $keyword]
    set keystart [string trimright $fullkey $keyend]
    lappend fullKeyList [list $keystart#$keyend abcdefghijklmnopqrstuvwxyz#]
    lappend fullKeyList [list $keyend#$keystart abcdefghijklmnopqrstuvwxyz#]
    lappend fullKeyList [list abcdefghijklmnopqrstuvwxyz# $keystart#$keyend]
    lappend fullKeyList [list abcdefghijklmnopqrstuvwxyz# $keyend#$keystart]

    return $fullKeyList
}

# Hillclimb::getRagbabyFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getRagbabyFullKeyList {keyword} {
    return [string map {j {} x {}} \
	    [key generate -k1 [string map {j i x w - {} ' {}} $keyword]]]
}

# Hillclimb::getAristocratFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getAristocratFullKeyList {keyword} {
    set fullKeyList {}
    #set fixedKey [key generate -k1 $keyword]
    foreach key [key generate -k1list $keyword] {
	# K1 key
	lappend fullKeyList [list abcdefghijklmnopqrstuvwxyz $key]
	#lappend fullKeyList $key
	# K2 key
	#lappend fullKeyList [list $key abcdefghijklmnopqrstuvwxyz]
	# K3 key
	#lappend fullKeyList [list $fixedKey $key]
    }

    return $fullKeyList
}

# Hillclimb::getK1FullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getK1FullKeyList {keyword} {
    set fullKeyList {}
    #set fixedKey [key generate -k1 $keyword]
    foreach key [key generate -k1list $keyword] {
	# K1 key
	lappend fullKeyList $key
	#lappend fullKeyList $key
	# K2 key
	#lappend fullKeyList [list $key abcdefghijklmnopqrstuvwxyz]
	# K3 key
	#lappend fullKeyList [list $fixedKey $key]
    }

    return $fullKeyList
}


# Hillclimb::getTwosquareFullKeyList
#
#	Generate a list of possible keys from a keyword.
#
# Arguments:
#
#	keyword		Keyword used to generate the key.
#
# Result:
#	A full keyed alphabet.

proc Hillclimb::getTwosquareFullKeyList {keyword} {
    set keypart1 [key generate -k1 [lindex $keyword 0]]
    regsub {j} $keypart1 {} keypart1

    set keypart2 [key generate -k1 [lindex $keyword 1]]
    regsub {j} $keypart2 {} keypart2

    return [list [list $keypart1 $keypart2]]
}

# Hillclimb::swapAristocratKey
#
#	Generate a list of neighbor keys for an aristocrat cipher
#	by swapping pairs of letters.
#
# Arguments:
#
#	key	Starting key for swapping.
#
# Result:
#	A list of modified kyes.

# This function has been reimplemented in C.  See hillclimb.c for details.

# Hillclimb::swapTwosquareKey
#
#	Generate a list of neighbor keys for a twosquare cipher
#	by swapping pairs of letters.
#
# Arguments:
#
#	key	Starting key for swapping.
#
# Result:
#	A list of modified kyes.

proc Hillclimb::swapTwosquareKey {key {fixedKeyPositions {}}} {
    set fullKeyList {}

    # Comingle the swapped keys so we can generate a little randomness
    # in the order of the returned keys.
    foreach key1 [generateSwapNeighborKeys [lindex $key 0] [lindex $fixedKeyPositions 0]] key2 [generateSwapNeighborKeys [lindex $key 1] [lindex $fixedKeyPositions 1]] {
	# We may get a different number of keys for each of the two alphabets
	# if there are a different number of fixed key positions for each key.
	if {$key1 != {}} {
	    lappend fullKeyList [list $key1 [lindex $key 1]]
	}
	if {$key2 != {}} {
	    lappend fullKeyList [list [lindex $key 0] $key2]
	}
    }

    return $fullKeyList
}

# Hillclimb::swapGenericKey
#
#	Generate a list of neighbor keys for a single n-letter alphabet.
#	Most cipher types will use this method to compute neighbor keys.
#
# Arguments:
#
#	key	Starting key for swapping.
#
# Result:
#	A list of modified kyes.

proc Hillclimb::swapGenericKey {key {fixedKeyPositions {}}} {
    return [generateSwapNeighborKeys $key $fixedKeyPositions]
}

# Hillclimb::mateGenericKeys2
#
#	Mate two keys with a two crossover points.
#
# Arguments:
#
#	parent1		First parent key
#	parent2		Second parent key
#
# Result:
#	Two new keys formed by 'mating' the parent keys.

proc Hillclimb::mateGenericKeys2 {parent1 parent2 {maxChromosomes -1} {firstCrossover -1} {secondCrossover -1}} {
    #puts "Mating $parent1 $parent2"
    if {[string length $parent1] != [string length $parent2]} {
        error "Can't perform a genetic crossover on gene sequences with differing lengths."
    }
    set geneLength [string length $parent1]

    if {$firstCrossover == -1} {
        set firstCrossover [expr int(rand()*($geneLength-2)+1)]
    }
    if {$maxChromosomes > 0} {
        set secondCrossover [expr {$firstCrossover + int(rand() * $maxChromosomes)}]
    } else {
        if {$secondCrossover == -1} {
            set secondCrossover [expr int(rand()*($geneLength-2)+1)]
        }
    }
    # Ensure that the first crossover point comes before the second.
    if {$firstCrossover > $secondCrossover} {
        set temp $firstCrossover
        set firstCrossover $secondCrossover
        set secondCrossover $temp
    }
    #puts "Crossing over at position $crossoverPosition"

    # Generate the first half of each offspring based on a single parent.
    set offspring1Start [string range $parent1 0 [expr {$firstCrossover-1}]]
    set offspring2Start [string range $parent2 0 [expr {$firstCrossover-1}]]
    set offspring1End [string range $parent1 $secondCrossover end]
    set offspring2End [string range $parent2 $secondCrossover end]
    #puts "Stable part of offspring 1: $offspring1Start...$offspring1End"
    #puts "Stable part of offspring 2: $offspring2Start...$offspring2End"

    # Generate the second half of each offspring by stripping the
    # elements inherited from the first parent out of the second parent.
    regsub -all "\[$offspring1Start$offspring1End\]" $parent2 {} offspringFragment
    #puts "second part of offspring 1: $offspringFragment"
    set offspring1 $offspring1Start$offspringFragment$offspring1End

    regsub -all "\[$offspring2Start$offspring2End\]" $parent1 {} offspringFragment
    #puts "second part of offspring 2: $offspringFragment"
    set offspring2 $offspring2Start$offspringFragment$offspring2End

    #puts "offspring1: $offspring1"
    #puts "offspring2: $offspring2"

    # Sanity check that the gene sequences for each offspring is the
    # same length as the parent gene sequences.
    if {[string length $offspring1] != $geneLength} {
        error "Generated offspring with an invalid gene sequence length:  $offspring1 ([string length $offspring1])"
    }
    if {[string length $offspring2] != $geneLength} {
        error "Generated offspring with an invalid gene sequence length:  $offspring2 ([string length $offspring2])"
    }

    return [list $offspring1 $offspring2]
}

# Hillclimb::mateGenericKeys
#
#	Mate two keys with a single crossover point.
#
# Arguments:
#
#	parent1		First parent key
#	parent2		Second parent key
#
# Result:
#	Two new keys formed by 'mating' the parent keys.

proc Hillclimb::mateGenericKeys {parent1 parent2 {maxChromosomes -1} {crossoverPosition -1}} {
    #puts "Mating $parent1 $parent2"
    if {[string length $parent1] != [string length $parent2]} {
        error "Can't perform a genetic crossover on gene sequences with differing lengths."
    }
    set geneLength [string length $parent1]

    if {$crossoverPosition == -1} {
        set crossoverPosition [expr int(rand()*($geneLength-2)+1)]
    }
    #puts "Crossing over at position $crossoverPosition"

    # Generate the first half of each offspring based on a single parent.
    set offspring1 [string range $parent1 0 [expr {$crossoverPosition-1}]]
    set offspring2 [string range $parent2 0 [expr {$crossoverPosition-1}]]
    #puts "First part of offspring 1: $offspring1"
    #puts "First part of offspring 2: $offspring2"

    # Generate the second half of each offspring by stripping the
    # elements inherited from the first parent out of the second parent.
    regsub -all "\[$offspring1\]" $parent2 {} offspringFragment
    #puts "second part of offspring 1: $offspringFragment"
    append offspring1 $offspringFragment

    regsub -all "\[$offspring2\]" $parent1 {} offspringFragment
    #puts "second part of offspring 2: $offspringFragment"
    append offspring2 $offspringFragment

    #puts "offspring1: $offspring1"
    #puts "offspring2: $offspring2"

    # Sanity check that the gene sequences for each offspring is the
    # same length as the parent gene sequences.
    if {[string length $offspring1] != $geneLength} {
        error "Generated offspring with an invalid gene sequence length:  $offspring1 ([string length $offspring1])"
    }
    if {[string length $offspring2] != $geneLength} {
        error "Generated offspring with an invalid gene sequence length:  $offspring2 ([string length $offspring2])"
    }

    return [list $offspring1 $offspring2]
}

# Hillclimb::mateAristocratKeys
#
#	Mate two aristocrat keys with a single crossover point.
#
# Arguments:
#
#	parent1		First parent key
#	parent2		Second parent key
#
# Result:
#	Two new keys formed by 'mating' the parent keys.

proc Hillclimb::mateAristocratKeys {parent1 parent2 {maxChromosomes -1} {crossoverPosition -1}} {
    set key1 [lindex $parent1 1]
    set key2 [lindex $parent2 1]

    foreach {offspring1 offspring2} [mateGenericKeys2 $key1 $key2 $maxChromosomes] {}

    return [list [list [lindex $parent1 0] $offspring1] [list [lindex $parent2 0] $offspring2]]
}

# Hillclimb::generateAristocratChurnKeylist
#
#	Generate a set of keys that substitute all possible substititions
#       for one position in the key
#
# Arguments:
#
#	ciphertype		Type of simple substitution cipher.
#	ctletter		The ciphertext letter to churn
#
# Result:
#	A list of keys that can be used as the starting point for hillclimbing

proc Hillclimb::generateSimpleChurnKeylist {ciphertype ctletter} {
    variable singleSeedKey

    set alphabet $singleSeedKey($ciphertype)
    set keyList {}
    for {set i 0} {$i < [string length $alphabet]} {incr i} {
        regsub -all "\[^$ctletter\]" $alphabet " " newKey
        regsub -all "\[^ \]" $newKey [string index $alphabet $i] newKey
        lappend keyList $newKey
    }

    return $keyList
}

proc Hillclimb::generatePhillipsChurnKeylist {ciphertype ctletter} {
    variable singleSeedKey

    set alphabet [string repeat " " 25]
    set alphabet [string replace $alphabet 22 22 $ctletter]
    set keyList {}
    for {set i 0} {$i < [string length $alphabet]} {incr i} {
        set newKey [string replace $alphabet 16 16 [string index $singleSeedKey(phillips) $i]]
        if {[string index $singleSeedKey(phillips) $i] != $ctletter} {
            lappend keyList $newKey
        }
    }

    return $keyList
}

# Hillclimb::generateUnsupportedChurnKeylist
#
#	Throw an error for cipher types that aren't able to use
#       churned keys
#
# Arguments:
#
#	type    		Type of unsupported cipher.  Used to
#                               customize the error message.
#	ctletter		unused
#
# Result:
#	Throws an error

proc Hillclimb::generateUnsupportedChurnKeylist {type ctletter} {
    error "Can not generate churn keys for this cipher type"
}
