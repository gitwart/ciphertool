# utils.tcl --
#
#	Some useful utility routines for ciphers.  Most of these
#	should eventually be rewritten in C for speed.  Eventually
#	these will probably get reorganized into other files.
#
# RCS: @(#) $Id: utils.tcl,v 1.28 2008/03/31 19:24:11 wart Exp $
#
# Copyright (C) 2002-2004  Mike Thomas <wart@kobold.org>
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

package provide CipherUtil 1.0

namespace eval CipherUtil {
    variable periodicTypes [list amsco beaufort bifid bigbifid bigplayfair columnar digrafid gromark gronsfeld myszcowski nicodemus playfair porta railfence route swagman trifid variant vigenere]
}

# CipherUtil::wordToOrder
#
#	Generate a numeric string that indicates the alphabetic order
#	of the letters in a word.  Example:  dog -> 132.  If there are
#	more than 9 letters in the word then the ordering is indeterminate;
#	values over 9 are reduced to a single digit.
#
# Arguments:
#
#	word		String to order-ify.
#	keepDups	(optional) boolean indicating if repeated letters
#			in a word should be given the same value.
#
# Result:
#	A numeric string.

proc CipherUtil::wordToOrder {word {keepDups 0}} {
    set letterList [lsort [split $word {}]]

    set value 1
    foreach letter $letterList {
	set orderValue [expr {$value % 10}]
	if {$keepDups} {
	    set newWord [string map "$letter $orderValue" $word]
	    if {! [string match $newWord $word]} {
		incr value
	    }
	    set word $newWord
	} else {
	    # If a letter appears more than once in the word then this will
	    # only change the first occurrence of the letter.
	    if {[regsub -- $letter $word $orderValue word]} {
		incr value
	    }
	}
    }

    return $word
}

# CipherUtil::generateKeysquares
#
#	Generate a set of keysquares from a word.  This routine first
#	generates a K1 keyed alphabet from the word, remove the 'j',
#	then applies 30+ routes to the key to generate keysqares.
#
# Arguments:
#
#	word		Keyword to use when generating the keyed alphabet.
#
# Result:
#	A list of keyed alphabets.

proc CipherUtil::generateKeysquares {word {width 5} {height 5}} {
    # Remove non-alphabetic characters (and 'j') when generating the key.  The
    # only non-alphabetic characters currently used by the dictionary are
    # hyphens and single apostrophes.
    set length [expr {$width * $height}]
    if {$length == 25} {
	set alphabet [string map {j {}} \
		[key generate -k1 [string map {j i - {} ' {}} $word]]]
    } elseif {$length == 27} {
	set alphabet [key generate -k1 [string map - {} ' {} $word]]#
    } else {
	error "CipherUtil::generateKeySquares:  Unsupported key size $length ($width x $height)"
    }

    set result {}
    set routeCipher [cipher create route -ct $alphabet -period $width]
    for {set route 1} {$route <= [$routeCipher cget -numroutes]} {incr route} {
	$routeCipher configure -in $route
	lappend result [$routeCipher cget -pt]
    }

    rename $routeCipher {}

    return $result
}

# CipherUtil::caesarShift
#
#	Perform a caesar shift on a set of characters.
#
# Arguments:
#
#	string		The string to shift.
#	shift		The amount which to shift.
#
# Result:
#	The shifted string.

proc CipherUtil::caesarShift {string shift} {
    set alphabet {abcdefghijklmnopqrstuvwxyz}
    set result {}

    # Convert negative shifts to a positive shift
    while {$shift < 0} {
	incr shift 26
    }

    foreach letter [split $string {}] {
	set alphIndex [string first $letter $alphabet]
	if {$alphIndex == -1} {
	    append result $letter
	} else {
	    set newIndex [expr {($alphIndex + $shift)%26}]
	    append result [string index $alphabet $newIndex]
	}
    }

    return $result
}

# CipherUtil::readCiphertext
#
#	Read a block of ciphertext from a file.
#
# Arguments:
#
#	filename	The name of the file containing the ciphertext, or
#			'-' if the ciphertext is to be read from standard
#			input.
#
# Result:
#	The ciphertext as a single-lined string.

proc CipherUtil::readCiphertext {filename} {
    if {$filename == "-"} {
	set fileid stdin
    } else {
	set fileid [open $filename r]
    }
    set lineSeparator ""
    set ct {}
    while {![eof $fileid]} {
	gets $fileid line
	if {$line != ""} {
	    append ct "$lineSeparator$line"
	    set lineSeparator " "
	}
    }
    if {$fileid != "stdin"} {
	close $fileid
    }

    return $ct
}

# CipherUtil::readSavedCipher
#
#	Read the data from a cipher savefile.
#
# Arguments:
#
#	filename	The name of the file containing the cipher data.
#
# Result:
#	A list of keys and values suitable for use as input to [array set]

proc CipherUtil::readSavedCipher {filename} {
    foreach var {ciphertext plaintext type period keyword keyval author title} {
	catch {unset $var}
    }
    set result {}

    set fileId [open $filename r]
    while {![eof $fileId]} {
	gets $fileId line
	if {[catch {llength $line}]} {
	    # The line is not a proper list.
	    puts stderr "Invalid list found for file $file, line $line"
	}

	if {[string index $line 0] == "#"} {
	    continue
	} elseif {[llength $line] != 2} {
	    continue
	}

	set index [lindex $line 0]
	set value [lindex $line 1]

	switch -exact -- $index {
	    type -
	    author -
	    title -
	    period -
	    keyword -
	    key -
	    ciphertext -
	    language -
	    plaintext {
		set $index $value
	    }
	}

	lappend result $index $value
    }
    close $fileId

    return $result
}

# CipherUtil::loadPropertiesFile
#
#	Load a java style properties file.
#
# Arguments:
#
#	filename	The name of the file to load.
#
# Result:
#	A list of key/value pairs suitable for use as input to [array set]

proc CipherUtil::loadPropertiesFile {filename} {
    set fileId [open $filename r]
    set foundContinuation 0
    set currentLine 0

    while {![eof $fileId]} {
	gets $fileId line
	if {$line == ""} {
	    continue
	}

	# Check for a multi-line value.
	if {$foundContinuation} {
	    append currentLine $line
	} else {
	    set currentLine $line
	}
	if {[string index $line end] == "\\"} {
	    set foundContinuation 1
	    set currentLine [string range $currentLine 0 end-2]
	    continue
	} else {
	    set foundContinuation 0
	}

	# We only get here after a complete line (or multi-line) has been
	# read.
	
	# Discard comments.
	if {[string index $currentLine 0] == "#"} {
	    set currentLine {}
	    continue
	}

	# Validate the format of the line itself and pull out the
	# key/value pair.
	set separatorIndex [string first "=" $currentLine]
	if {$separatorIndex == -1} {
	    close $fileId
	    error "Invalid line in file:  no separator found:  $currentLine"
	}

	set key [string range $currentLine 0 [expr {$separatorIndex-1}]]
	set value [string range $currentLine [expr {$separatorIndex+1}] end]
	if {[string length $key] == 0} {
	    close $fileId
	    error "Invalid line in file:  key length is zero:  $currentLine"
	}

	# Check for a duplicate key
	if {[info exists parms($key)]} {
	    close $fileId
	    error "Duplicate key found in file '$filename':  $key"
	}

	set parms($key) $value
    }

    close $fileId

    return [array get parms]
}

# CipherUtil::loadCipher
#
#	Load a single cipher from a file.
#
# Arguments:
#
#	filename	The name of the file containing the cipher data.
#	id		The id of the cipher to select.  If no id is
#			given then the default (no id) cipher is returned.
#
# Result:
#	A list of key/value pairs suitable for use as input to [array set].
#	if no matching id was found then an empty list is returned.

proc CipherUtil::loadCipher {filename {id {}}} {
    set result {}

    array set cipherData [loadPropertiesFile $filename]

    foreach el [array names cipherData] {
	# Pull out the cipher id from the key.
	if {[regexp {(^[^\.]+)\.(.*)} $el null cipherid key] == 0} {
	    set cipherid {}
	    set key $el
	}

	if {$cipherid == $id} {
	    lappend result $key $cipherData($el)
	}
    }

    return $result
}

# CipherUtil::createCipherFromFile
#
#	Create a cipher object from a cipher description in a file.
#
# Arguments:
#
#	filename	The name of the file containing the cipher data.
#	id		The id of the cipher to select.  If no id is
#			given then the default (no id) cipher is returned.
#
# Result:
#	A cipher object (implemented as a Tcl command).  An error is
#	thrown if there was a problem creating the cipher object.

proc CipherUtil::createCipherFromFile {filename {id {}}} {
    variable periodicTypes

    array set cipherData [loadCipher $filename $id]

    if {![info exists cipherData(ciphertext)]} {
	error "No ciphertext found for cipher."
    }

    if {![info exists cipherData(type)]} {
	error "No type found for cipher."
    }

    set cipherObj [cipher create $cipherData(type) -ct $cipherData(ciphertext)]

    if {[lsearch $periodicTypes $cipherData(type)] != -1} {
	if {[info exists cipherData(period)]} {
	    $cipherObj configure -period $cipherData(period)
	}
    }

    if {[info exists cipherData(key)]} {
	switch $cipherData(type) {
	    amsco -
	    columnar -
	    myszcowski {
		# Strip off the optional quotation marks from both the start
		# and the end.
		if {[string index $cipherData(key) 0] == "\"" \
		    && [string index $cipherData(key) end] == "\""} {

		    set cipherData(key) [string range $cipherData(key) 1 end-1]
		}

		if {![info exists cipherData(period)]} {
		    $cipherObj configure \
			    -period [string length $cipherData(key)]
		}

		$cipherObj restore $cipherData(key)
	    }
	    grandpre -
	    grille -
	    gromark -
	    nitrans -
	    phillips -
	    playfair -
	    bigplayfair -
	    ragbaby -
	    swagman -
	    trifid {
		# Strip off the optional quotation marks from both the start
		# and the end.
		if {[string index $cipherData(key) 0] == "\"" \
		    && [string index $cipherData(key) end] == "\""} {

		    set cipherData(key) [string range $cipherData(key) 1 end-1]
		}
		$cipherObj restore $cipherData(key)
	    }
	    bifid -
	    bigbifid {
		if {[llength $cipherData(key)] == 1} {
		    $cipherObj restore [lindex $cipherData(key) 0]
		} else if {[llength $cipherData(key)] == 2} {
		    $cipherObj restore [lindex $cipherData(key) 0] \
			    [lindex $cipherData(key) 1]
		} else {
		    rename $cipherObj {}
		    error "Too many parts found in the $cipherData(type) '$id' key:  $cipherData(key)"
		}
	    }
	    aristocrat -
	    baconian -
	    fmorse -
	    morbit -
	    pollux -
	    foursquare -
	    twosquare -
	    homophonic {
		if {[llength $cipherData(key)] != 2} {
		    rename $cipherObj {}
		    error "Wrong # parts found in the $cipherData(type) '$id' key:  $cipherData(key)"
		} else {
		    $cipherObj restore [lindex $cipherData(key) 0] \
			    [lindex $cipherData(key) 1]
		}
	    }
	    route {
		if {[llength $cipherData(key)] != 2} {
		    rename $cipherObj {}
		    error "Wrong # parts found in the $cipherData(type) '$id' key:  $cipherData(key)"
		}
		if {![info exists cipherData(period)]} {
		    error "No period found for saved route cipher."
		}

		$cipherObj restore [lindex $cipherData(key) 0] \
			[lindex $cipherData(key) 1]
	    }
	    nicodemus {
		if {[llength $cipherData(key)] != 2} {
		    rename $cipherObj {}
		    error "Wrong # parts found in the $cipherData(type) '$id' key:  $cipherData(key)"
		}

		if {![info exists cipherData(period)]} {
		    $cipherObj configure -period \
			    [string length [lindex $cipherData(key) 0]]
		}

		$cipherObj restore [lindex $cipherData(key) 0] \
			[lindex $cipherData(key) 1]
	    }
	    beaufort -
	    vigenere -
	    variant -
	    gronsfeld -
	    porta {
		if {[llength $cipherData(key)] != 2} {
		    rename $cipherObj {}
		    error "Wrong # parts found in the $cipherData(type) '$id' key:  $cipherData(key)"
		}

		if {![info exists cipherData(period)]} {
		    $cipherObj configure -period \
			    [string length [lindex $cipherData(key) 0]]
		}

		$cipherObj restore [lindex $cipherData(key) 0] \
			[lindex $cipherData(key) 1]
	    }
	}
    }

    return $cipherObj
}

# CipherUtil::writeCipherToFile
#
#	Write a cipher object to a file so that it can be loaded again later.
#
# Arguments:
#
#	cipherObj	The cipher object to write.
#	chanid		The open channel to which to write the cipher.
#			If no channel is specified then the cipher is
#			written to stdout.
#	id		The id of the cipher in the output file.  This
#			is necessary when multiple ciphers are written to
#			the same file.
#
# Result:
#	A cipher object (implemented as a Tcl command).  An error is
#	thrown if there was a problem creating the cipher object.

proc CipherUtil::writeCipherToFile {cipherObj {chanid stdout} {id {}}} {
    if {$id == ""} {
	set idPrefix {}
    } else {
	set idPrefix ${id}.
    }
    puts $chanid "${idPrefix}type=[$cipherObj cget -type]"
    puts $chanid "${idPrefix}period=[$cipherObj cget -period]"
    puts $chanid "${idPrefix}ciphertext=[$cipherObj cget -ciphertext]"
    puts $chanid "${idPrefix}plaintext=[$cipherObj cget -plaintext]"
    puts $chanid "${idPrefix}key=[$cipherObj cget -key]"
    catch {puts $chanid "${idPrefix}keyword=[$cipherObj cget -keyword]"}
    puts $chanid "${idPrefix}language=[$cipherObj cget -language]"
    puts $chanid "# Score value:  [score value [$cipherObj cget -pt]]"

    switch [$cipherObj cget -type] {
	aristocrat {
	    puts $chanid "${idPrefix}k1key=[lindex [$cipherObj cget -K1key] 1]"
	    puts $chanid "${idPrefix}alfbt=abcdefghijklmnopqrstuvwxyz"
	    puts $chanid "${idPrefix}k2key=[lindex [$cipherObj cget -K2key] 1]"
	}
	baconian {
	    set btext [$cipherObj cget -btext]
	    puts -nonewline $chanid "${idPrefix}bacontext="
	    while {[regexp (.....) $btext null word]} {
		regsub ..... $btext {} btext
		puts -nonewline $chanid "$word "
	    }
	    puts ""
	}
	grandpre {
	    set key [$cipherObj cget -key]
	    for {set i 0} {$i < 8} {incr i} {
		set keyword [string range [lindex $key 1] [expr {$i * 8}] [expr {$i * 8 + 7}]]
		puts $chanid "${idPrefix}keyword.$i=$keyword"
	    }

	}
	porta {
	    set keyword [$cipherObj cget -keyword]

	    puts $chanid "${idPrefix}keyword1=[lindex $keyword 0]"
	    puts $chanid "${idPrefix}keyword2=[lindex $keyword 1]"
	}
	swagman {
	    set pt [$cipherObj cget -ptblock]
	    for {set i 0} {$i < [$cipherObj cget -period]} {incr i} {
		puts $chanid "${idPrefix}plaintext.$i=[lindex $pt $i]"
	    }

	    set ct [$cipherObj cget -ctblock]
	    for {set i 0} {$i < [$cipherObj cget -period]} {incr i} {
		puts $chanid "${idPrefix}ciphertext.$i=[lindex $ct $i]"
	    }

	    set key [$cipherObj cget -key]
	    for {set i 0} {$i < [$cipherObj cget -period]} {incr i} {
		puts $chanid "${idPrefix}key.$i= [lindex $key $i]"
	    }
	}
	nicodemus {
	    puts $chanid "${idPrefix}encoding=[$cipherObj cget -encoding]"
	}
	fmorse {
	    puts $chanid "${idPrefix}morsetext=[$cipherObj cget -mt]"
	}
	gromark {
	    if {[$cipherObj cget -chain] != ""} {
		puts $chanid "${idPrefix}chain=[$cipherObj cget -chain]"
	    }
	}
	default {
	}
    }

    return {}
}

# CipherUtil::loadK3Fragments
#
#	Load k3 alphabet fragments from an aristocrat/patristocrat save file.
#
# Arguments:
#
#	filename	The name of the file containing the cipher data.
#
# Result:
#	A list of k3 alphabet fragments.

proc CipherUtil::loadK3Fragments {filename} {
    array set cipherdata [CipherUtil::loadCipher $filename]

    set cipher [cipher create aristocrat -ct $cipherdata(ciphertext)]
    $cipher restore [lindex $cipherdata(key) 0] [lindex $cipherdata(key) 1]

    set keyPt [lindex $cipherdata(key) 0]
    set keyCt [lindex $cipherdata(key) 1]

    for {set i 0} {$i < [string length $keyPt]} {incr i} {
	if {[string index $keyCt $i] == " "} {
	    set follows([string index $keyPt $i]) ""
	} else {
	    set follows([string index $keyPt $i]) [string index $keyCt $i]
	}
    }

    set foundTail 1
    while {$foundTail} {
	set foundTail 0
	foreach el [array names follows] {
	    # We need this extra check because we have have deleted the
	    # current entry on a previous pass.
	    if {[info exists follows($el)]} {
		set value [string index $follows($el) end]
		if {[info exists follows($value)] && $el != $value} {
		    #puts "set follows($el) $follows($el)$follows($value)"
		    set follows($el) $follows($el)$follows($value)
		    array unset follows $value

		    set foundTail 1
		}
	    }
	}
    }

    set result {}
    foreach el [array names follows] {
	set value [string index $follows($el) end]
	if {$value != $el} {
	    lappend result $el$follows($el)
	} else {
	    lappend result $follows($el)
	}
    }

    return $result
}

# CipherUtil::lreverse
#
#	Reverse a list.
#
# Arguments:
#
#	List	The list of items to reverse.
#
# Result:
#	A reversed list.

proc CipherUtil::lreverse {List} {
    for {set i [expr {[llength $List] - 1}]} {$i >= 0} {incr i -1} {
        lappend Li1r [lindex $List $i]
    }
    return $Li1r
}

# CipherUtil::phillipsIoc
#
#	Calculate the index of coincidence for the 6 unique blocks
#	of a phillips cipher.
#
# Arguments:
#
#	ctext	The phillips ciphertext.
#
# Result:
#	A list of 7 indices of coincidence.  The final 6 are for the 6
#	unique phillips blocks, and the first is the average of the 6.

proc CipherUtil::phillipsIoc {ct} {
    set period 8
    set totalIoc 0
    set result {}

    for {set i 1} {$i <= $period} {incr i} {
	set columnCt($i) {}
    }

    for {set pos 0} \
	{$pos < [string length $ct]} \
	{incr pos 5} {

	append columnCt([expr {$i + 1}]) \
		[string range $ct $pos [expr {$pos + 4}]]
	set i [expr {($i + 1) % $period}]
    }

    # Squares 1 and 5 are the same for phillips, as are squares
    # 2 and 8.
    append columnCt(1) $columnCt(5)
    append columnCt(2) $columnCt(8)
    set columnCt(5) $columnCt(1)
    set columnCt(8) $columnCt(2)

    for {set i 1} {$i <= $period} {incr i} {
	lappend result [stat ioc $columnCt($i)]
	set totalIoc [expr {$totalIoc + [stat ioc $columnCt($i)]}]
    }

    return [concat [expr {$totalIoc / $period}] $result]
}

# CipherUtil::periodicIoc
#
#	Calculate the index of coincidence for each group of a periodic cipher.
#
# Arguments:
#
#	period	The cipher's period
#	ctext	The ciphertext.
#
# Result:
#	A list of n+1 indices of coincidence.  The first is the average of
#	all, and the final n are for each of the periodic groups.

proc CipherUtil::periodicIoc {period ct} {
    set totalIoc 0
    set result {}

    for {set i 1} {$i <= $period} {incr i} {
	set columnCt($i) {}
    }

    for {set i 1} {$i <= $period} {incr i} {
	for {set pos $i} \
	    {$pos < [string length $ct]} \
	    {incr pos $period} {

	    append columnCt($i) [string index $ct $pos]
	}
    }

    for {set i 1} {$i <= $period} {incr i} {
	lappend result [stat ioc $columnCt($i)]
	set totalIoc [expr {$totalIoc + [stat ioc $columnCt($i)]}]
    }

    return [concat [expr {$totalIoc / $period}] $result]
}

# CipherUtil::aristocratKeyToColumnar
#
#	Convert the key of an aristocrat cipher object to a columnar
#       object.  This can aid in recovering K3/K4 keywords.
#
# Arguments:
#
#	cipherObj	An aristocrat cipher object, such as returned from
#                       [cipher create aristocrat] or
#                       [CipherUtil::createCipherFromFile]
#
# Result:
#	A columnar cipher object.

proc CipherUtil::aristocratKeyToColumnar {cipherObj {type {}}} {
    if {[$cipherObj cget -type] != "aristocrat"} {
        error "aristocratKeyToColumnar called on a non-aristocrat cipher."
    }

    set k1key    [string map {{ } -} [lindex [$cipherObj cget -K1key] 1]]
    set alphabet "abcdefghijklmnopqrstuvwxyz"
    set k2key    [string map {{ } -} [lindex [$cipherObj cget -K2key] 1]]

    set colCiphertext {}
    for {set i 0} {$i < 26} {incr i} {
        switch $type {
            k1 {
                append colCiphertext [string index $k1key $i][string index $alphabet $i]
            }
            k2 {
                append colCiphertext [string index $alphabet $i][string index $k2key $i]
            }
            default {
                append colCiphertext [string index $k1key $i][string index $alphabet $i][string index $k2key $i]
            }
        }
    }

    set colCipher [cipher create columnar -ciphertext $colCiphertext -period 26]

    return $colCipher
}

# CipherUtil::checkerboard2pat
#
#	Convert a string of checkerboard ciphertext to patristocrat ciphertext.
#
# Arguments:
#
#	ct	A string of checkerboard ciphertext.  Only a 5x5
#               checkerboard can be used.
#
# Result:
#	A set of key-value pairs where each key is a checkerboard digram
#       and the value is the patristocrat replacement.  A few special keys
#       are used to give information about the transformation:
#           'ct' contains the patristocrat ciphertext.
#           'pre' contains the set of initial letters in the checkerboard
#                 keysquare
#           'post' contains the set of initial letters in the checkerboard
#                 keysquare

proc CipherUtil::checkerboard2pat {ct} {
    set validChars abcdefghijklmnopqrstuvwxyz0123456789

    set firstLetters {}
    set secondLetters {}
    set validIndex 0
    for {set i 0} {$i < [string length $ct]} {incr i} {
        set letter [string index $ct $i]
        if {[string first $letter $validChars] != -1} {
            if {$validIndex % 2 == 0} {
                if {[string first $letter $firstLetters] == -1} {
                    append firstLetters $letter
                }
            } else {
                if {[string first $letter $secondLetters] == -1} {
                    append secondLetters $letter
                }
            }
            incr validIndex
        }
    }

    for {set i 0} {$i < 5} {incr i} {
        for {set j 0} {$j < 5} {incr j} {
            set alphabetIndex [expr {$i * 5 + $j}]
            if {$alphabetIndex >= 9} {
                incr alphabetIndex
            }
            set ct1 [string index $firstLetters $i]
            set ct2 [string index $secondLetters $j]
            set map($ct1$ct2) [string index $validChars $alphabetIndex]
        }
    }

    set map(ciphertext) [string map [array get map] $ct]
    set map(pre) $firstLetters
    set map(post) $secondLetters

    return [array get map]
}
