# scoredata.tcl --
#
#	Some useful utility routines for custom scoring methods and
#	tables.
#
# RCS: @(#) $Id: scoredata.tcl,v 1.10 2005/04/14 20:03:10 wart Exp $
#
# Copyright (C) 2004  Mike Thomas <wart@kobold.org>
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

package provide Scoredata 1.0

namespace eval Scoredata {
    variable allowedCharacters "abcdefghijklmnopqrstuvwxyz"
    variable dataDir {}
}

namespace eval Scoredata "set dataDir [file dirname [info script]]"

# Scoredata::loadData
#
#	Load precalculated normalized scoring data from a file.  The file must
#	have the following format:  Each line must be a single "score add"
#	command, using $s as the score command:
#		$s add abc 42
#	Note that lines with a value of 0 aren't necessary as the
#	score commands default all values to 0.
#
# Arguments:
#
#	command		The score command that will load the data.
#	filename	(optional) The name of the file from which the
#			data will be loaded.  If not specified, then
#			a preexisting file will be used, based on the
#			score command type.
#
# Result:
#	None.

proc Scoredata::loadData {command {language {}} {filename {}}} {
    variable dataDir

    # Wordtrees are created differently from the other types.
    if {[$command type] == "wordtree"} {
        Dictionary::createWordTree $command
        # createWordTree does not normalize the data, as has already been
        # done with the other score types that are read in from files.
        $command normalize
        return {}
    }

    if {$filename == ""} {
	set type [$command type]
	if {[string first ngram $type] == 0} {
	    set type [$command elemsize][string range $type 1 end]
	}

        if {$language == ""} {
            set filename [file join $dataDir ${type}Data.tcl]
        } else {
            set filename [file join $dataDir ${type}Data_${language}.tcl]
        }
    }

    set s $command
    source $filename

    return {}
}

# Scoredata::saveData
#
#	Save a scoring table to a file for later use.  Elements in the
#	table with a value of '0' are not saved since that is the default
#	value of a scoring table element.
#
# Arguments:
#
#	command		The score command that will load the data.
#	filename	The name of the file to which the data will be
#	                saved.
#
# Result:
#	None.

proc Scoredata::saveData {command filename} {
    if {$filename == "-"} {
	set fileid stdout
    } else {
	set fileid [open $filename w]
    }

    $command dump "Scoredata::writeSaveLine $fileid"

    if {$filename != "-"} {
	close $fileid
    }

    return {}
}

proc Scoredata::writeSaveLine {fileid saveData} {
    puts $fileid "\$s add $saveData"
}

# Scoredata::generate
#
#	Load new scoring data from a set of text files.  Frequency counts
#	are generated on the fly from the text in the input files.  The
#	score data is normalized.
#
# Arguments:
#
#	command		The score command that will load the data.
#	args		The names of the files from which the
#			data will be calculated.
#
# Result:
#	None.

proc Scoredata::generate {command args} {
    variable allowedCharacters

    set elemSize [$command elemsize]

    foreach file $args {
	set ptstring {}

	set fileId [open $file r]
	while {![eof $fileId]} {
	    if {$elemSize == 0} {
		gets $fileId line
		foreach word [split $line] {
		    regsub -all "\[^$allowedCharacters\]" $word {} word
		    $command add $word
		}
	    } else {
		set letter [read $fileId 1]
		if {[string first $letter $allowedCharacters] != -1} {
		    append ptstring $letter
		    set ptstring [string range $ptstring [expr [string length $ptstring]-$elemSize] end]

		    if {[string length $ptstring] == $elemSize} {
			$command add $ptstring 1.0
		    }
		}
	    }
	}
	close $fileId
    }

    $command normalize

    return {}
}
