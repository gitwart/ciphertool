# crithm.tcl --
#
#	Library routines for performing brute force searches on
#	cryptarithm ciphers.
#
# RCS: @(#) $Id: crithm.tcl,v 1.6 2005/11/08 22:13:50 wart Exp $
#
# Copyright (C) 2000  Mike Thomas <wart@kobold.org>
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

package provide Crithm 1.0

# A base-9  cryptarithm has    362880 possible solutions
# A base-10 cryptarithm has   3628800 possible solutions
# A base-11 cryptarithm has  39916800 possible solutions
# A base-12 cryptarithm has 479001600 possible solutions

namespace eval Crithm {
    variable iterCount 0
    variable stepInterval 200000
    variable solutionList {}
    variable nonzeroLetters {}
}

# Crithm::start
#
#	This routine initializes the crithm permutation generator and then
#	starts it off.
#
# Arguments:
#
#	letters		List of letters in the cipher
#
# Result:
#	None.

proc Crithm::start {letters} {
    variable solutionList

    set solutionList {}
    crithm delete

    crithm init $letters Crithm::permProc

    crithm perm
}

# Crithm::checkKey
#
#	This routine is a stub.  Users are required to write their own
#	checkKey implementation.  This routine needs to determine if the
#	current set of values put in place by the permutation engine are
#	a valid solution.
#
# Arguments:
#	None.
#
# Result:
#	This routine should return 1 if the solution is valid, 0 otherwise.

proc Crithm::checkKey {} {
    error "You must write your own Crithm::checkKey procedure to continue"
}

# Crithm::sortKey
#
#	Sort an array numerically by it's values.
#
# Arguments:
#	keyList		List of key-value pairs suitable for input to
#			"array set".  values must be non-negative integers,
#			with the maximum value not exceeding the length of
#			the list.
#
# Result:
#	Returns a pair of lists.  The first list contains the ordered
#	values, and the second list contains the corresponding keys.

proc Crithm::sortKey {keyList} {
    array set keyArr $keyList

    set indices {}
    set values {}

    for {set i 0} {$i < [llength [array names keyArr]]} {incr i} {
	foreach el [array names keyArr] {
	    if {$keyArr($el) >= [llength [array names keyArr]]} {
		error "Bad key value $keyArr($el).  Must be less than the\
			length of the list"
	    }
	    if {$keyArr($el) == $i} {
		lappend indices $el
		lappend values $i
	    }
	}
    }

    return [list $indices $values]
}

# Crithm::permProc
#
#	Perform a solution check at every calculated permutation.  This
#	function is called every time the permutation engine generates
#	another permutation.
#
# Arguments:
#	None.
#
# Side Effects:
#	Text will be written to stdout.
#	The global variable "solutionList" will be updated to contain the
#	newly-found solution.
#
# Result:
#	None.

proc Crithm::permProc {} {
    variable iterCount
    variable stepInterval
    variable solutionList

    incr iterCount

    if {[checkKey]} {
	puts ""
	puts "# $iterCount: SOLUTION"
	puts "# [lindex [sortKey [crithm state]] 0]"
	puts "# [lindex [sortKey [crithm state]] 1]"
	lappend ::Crithm::solutionList [lindex [sortKey [crithm state]] 0]
    }

    if {($iterCount % $stepInterval) == 0} {
	puts ""
	puts "# $iterCount:"
	puts "# [lindex [sortKey [crithm state]] 0]"
	puts "# [lindex [sortKey [crithm state]] 1]"
    }

    return
}

# Crithm::createNonzeroConstraint
#
#	Create code that will check if the current permutation engine
#	values satisfy given input conditions.  This particular constraint
#       generator looks for multi-letter words and enforces that the first
#       letter of each word can not be zero.
#
# Arguments:
#	expression	A cryptarithm constraint such as "dog + cat = food"
#
# Result:
#	A list of constraints, each of which is Tcl code that returns either 1
#	or 0 when eval'd.

proc Crithm::createNonzeroConstraint {expression} {
    set constraintList {}

    regsub -all {^([a-z])[^a-z]} $expression {} expression
    regsub -all {[^a-z]([a-z])$} $expression {} expression
    regsub -all {[^a-z]([a-z])[^a-z]} $expression {} expression
    if {[regsub -all {([a-z])[a-z]+} $expression {\1} result] > 0} {
        regsub -all {[^a-z]} $result {} result
        foreach letter [split $result {}] {
            lappend constraintList "\[crithm cvalue $letter\] != 0"
        }
    }

    return $constraintList
}

# Crithm::createConstraint
#
#	Create code that will check if the current permutation engine
#	values satisfy given input conditions.
#
# Arguments:
#	equation	List of either 5 or 7 elements.   Must match one
#			of the following patterns:
#			A op B == C
#			A op B == C op D
#
# Result:
#	Tcl code that returns either 1 or 0 when eval'd.

proc Crithm::createConstraint {args} {
    set eqLength [llength $args]
    if {$eqLength == 1} {
        set constraint [lindex $args 0]
    } else {
        set constraint [concat $args]
    }
    if {! [regexp {^([^=]+)==?([^=]+)$} $constraint null lhs rhs]} {
        error "Could not create a constraint from '$args'.  Missing '=' comparator."
    }

    set lhsCode [wordToCode $lhs]
    set rhsCode [wordToCode $rhs]

    set code "$lhsCode == $rhsCode"

    return $code
}

# Crithm::wordToCode
#
#	Convert a string to either a number or tcl code that will
#	evaluate to a number.
#
# Arguments:
#	string		String to codify
#
# Result:
#	One of:  a number (such as 42 or 0), or a tcl expression that
#	will evaluate to a number (such as [expr {4 + 5}])

proc Crithm::wordToCode {string} {
    set string [string trim $string]
    set type [getWordType $string]

    switch $type {
	string {
	    set code "\[crithm value $string\]"
	}
	letter {
	    set code "\[crithm cvalue $string\]"
	}
	number {
	    set code $string
	}
        expression {
            if {[regexp {(\S+)\s*([-+])\s*(\S+)} $string null lhs op rhs]} {
                set code "([wordToCode $lhs] $op [wordToCode $rhs])"
            } elseif {[regexp {(\S+)\s*([*/])\s*(\S+)} $string null lhs op rhs]} {
                set code "([wordToCode $lhs] $op [wordToCode $rhs])"
            } elseif {[regexp {(\S+)\s*(\^)\s*(\S+)} $string null lhs op rhs]} {
                set code "pow([wordToCode $lhs], [wordToCode $rhs])"
            } else {
                error "Could not evaluate $string as an expression.  Why wasn't this caught by getWordType?"
            }
        }
	default {
	    error "Can't evaluate $string as an expression"
	}
    }

    return $code
}

# Crithm::getWordType
#
#	Determine if a given word is a string, single letter, or number.
#
# Arguments:
#	value		Value to analyze
#
# Result:
#	one of "string", "letter", "number", or "unknown"

proc Crithm::getWordType {value} {
    set type unknown

    if {[regexp {^[0-9]+$} $value]} {
	set type number
    } elseif {[regexp {^[a-zA-Z]$} $value]} {
	set type letter
    } elseif {[regexp {^[a-zA-Z]+$} $value]} {
	set type string
    } elseif {[regexp {.[-+*/^].} $value]} {
        set type expression
    } else {
	set type unknown
    }

    return $type
}

# Crithm::isValidOperator
#
#	Determine if a given character is a valid mathematical operator
#
# Arguments:
#	char		Character to analyze
#
# Result:
#	1 if the character is valid, 0 if not.

proc Crithm::isValidOperator {char} {
    switch -- $char {
	+ -
	* -
	- -
	/ -
        ^ {
	    return 1
	}
	default {
	    return 0
	}
    }
}

# Crithm::getUniqueLetters
#
#	Given an arbitrary string, calculate a sorted list of the unique
#	letters in the string.  Non-alphabetic characters are ignored.
#
# Arguments:
#	string		String to unique-ify
#
# Result:
#	Returns a sorted string with unique letters

proc Crithm::getUniqueLetters {string} {
    regsub -all {[^a-zA-Z]} $string {} string

    set letlist [join [lsort -unique [split $string {}]] {}]

    return $letlist
}

# Crithm::createCheckKeyProc
#
#	Creates a Crithm::checkKey procedure body from a list of constraints.
#
# Arguments:
#	constraintList	List of constraints, as returned from
#			Crithm::createConstraint
#
# Result:
#	Returns a string that can be used as a procedure body.

proc Crithm::createCheckKeyProc {constraintList} {
    set procBody {}

    foreach constraint $constraintList {
	append procBody "\n    if \{$constraint\} \{"
    }
    if {[llength $constraintList] > 0} {
	append procBody "\n        return 1"
    }
    foreach constraint $constraintList {
	append procBody "\n    \}"
    }
    append procBody "\n\n    return 0\n"

    return $procBody
}

# Crithm::sortByLength
#
#	Compares two constraings and returns 1 if the first constraint
#       is longer, 0 if they are the same length, and -1 if the first
#       is shorter.
#       The time it takes to evaluate a constraint expression is roughly
#       proportional to its length.  By sorting constraints by length, we can
#       actually reduce the time it takes to solve a cipher.
#
# Arguments:
#	constraintList	List of constraints, as returned from
#			Crithm::createConstraint
#
# Result:
#	A sorted list of constraints.

proc Crithm::sortByLength {a b} {
    return [expr {[string length $a] - [string length $b]}]
}

# Crithm::saveCipherFile
#
#	Saves a list of constraints to a file in a format that can
#	be run eval'd by a Tcl interpreter.
#
# Arguments:
#	filename	Name of file to create
#	letterString	String of unique letters in the cipher
#	constraintList	List of constraints, as returned from
#			Crithm::createConstraint
#
# Result:
#	None.

proc Crithm::saveCipherFile {filename letterString constraintList {solfile {}}} {
    set procBody [createCheckKeyProc [lsort -command Crithm::sortByLength [lsort -unique $constraintList]]]
    if {$solfile == ""} {
	set solfile $filename.out
    }

    if {$filename != "stdout"} {
        set chanId [open $filename w]
    } else {
        set chanId stdout
    }
    puts $chanId {#!/bin/sh}
    puts $chanId "# \\"
    puts $chanId {exec tclsh "$0" ${1+"$@"}}
    puts $chanId ""
    puts $chanId "package require cipher"
    puts $chanId "package require Crithm"
    puts $chanId ""
    puts $chanId "proc Crithm::checkKey \{\} \{"
    puts $chanId $procBody
    puts $chanId "\}"
    puts $chanId ""
    puts $chanId "Crithm::start [list $letterString]"
    puts $chanId ""
    puts $chanId "Crithm::saveSolution $solfile"
    puts $chanId "Crithm::saveSolution stdout"

    if {$chanId != "stdout"} {
        close $chanId
    }

    return
}

# Crithm::saveSolution
#
#	Saves the list of solution strings to a file in the standard
#	cryptarithm output format.
#
# Arguments:
#	filename	Name of file to create
#
# Result:
#	None.

proc Crithm::saveSolution {filename} {
    variable solutionList

    if {$filename == "stdout"} {
	set chanId stdout
    } elseif {$filename == "stderr"} {
	set chanId stderr
    } else {
	set chanId [open $filename w]
    }
    puts $chanId "type=cryptarithm"
    puts $chanId "ciphertext={}"
    puts $chanId "key=[string map [list { } {}] [lindex $solutionList 0]]"
    puts $chanId "keyword=[string map [list { } {}] [lindex $solutionList 0]]"
    puts $chanId "plaintext=[string map [list { } {}] [lindex $solutionList 0]]"
    foreach extraKey [lrange $solutionList 1 end] {
	puts $chanId ""
	puts $chanId \
		"#key\t[string map [list { } {}] [lindex $solutionList 0]]"
	puts $chanId \
		"#keyword\t[string map [list { } {}] [lindex $solutionList 0]]"
	puts $chanId \
		"#plaintext\t[string map [list { } {}] [lindex $solutionList 0]]"
    }
    close $chanId

    return
}
