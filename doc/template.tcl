# template.tcl --
#
#	Library routines for generating documentation.
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

proc docHeader {title} {
    set result "<HTML>\n"
    append result "<TITLE>$title</TITLE>\n"
    append result "<BODY BGCOLOR=white>\n"

    return $result
}

proc footer {} {
    set result "\n<HR>\n"
    append result "<A HREF=\"index.html\">Back to the Index</A>\n"
    append result "<BR>\n"
    append result "<I><A HREF=\"mailto:wart@kobold.org\">wart@kobold.org</A></I>\n"
    append result "<BR>\n"
    append result "<I>Created on [clock format [clock seconds]]</I>\n"
    append result "<BR>\n"
    append result "<a href=\"http://sourceforge.net\"><img src=\"http://sourceforge.net/sflogo.php?group_id=86325&amp;type=2\" width=\"125\" height=\"37\" border=\"0\" alt=\"SourceForge.net Logo\" /></a>"
    append result "</BODY>\n"
    append result "</HTML>\n"

    return $result
}

proc Command {command desc} {
    set result "<H2>NAME</H2>\n"
    append result "$command - $desc\n"

    return $result
}

proc Procedures {} {
    set result "<H2>COMMANDS</H2>\n"

    return $result
}

proc Variables {} {
    set result "<H2>VARIABLES</H2>\n"

    return $result
}

proc Link {location string} {
    set result "<A HREF=\"$location\">$string</A>"

    return $result
}

proc Ciphertype {type} {
    global cipherType
    set cipherType $type

    return [Command $type "Create and manipulate a $type cipher"]
}

proc SynopsisHeader {} {
    set result "<H2>SYNOPSIS</H2>\n"

    return $result
}

proc Synopsis {command options args} {
    set tag {}

    if {[llength $args] != 0} {
	set tag [lindex $args 0]
    }

    if {$tag == ""} {
	set result "<B>$command</B> <I>$options</I>\n"
    } else {
	set result "<A HREF=\"#$tag\"><B>$command</B> <I>$options</I></A>\n"
    }
    append result "<BR>\n"

    return $result
}

proc StartDescription {{header {DESCRIPTION}}} {
    set result "<H2>$header</H2>\n"
    append result "<DL>\n"

    return $result
}

proc Description {usage tag longDesc} {
    global usageArr
    global usageList

    set usageArr($usage) $longDesc
    lappend usageList $usage

    append result "    <P>\n"
    if {$tag != ""} {
	append result "    <DT><A NAME=\"$tag\"><B><CODE>$usage</CODE></B></A></DT>\n"
    } else {
	append result "    <DT><B><CODE>$usage</CODE></B></DT>\n"
    }
    append result "        <DD>$longDesc\n"
    append result "        </DD>\n"

    return $result
}

proc EndDescription {} {
    set result "</DL>\n"

    return $result
}

proc DictionaryDescription {} {
    set result "The dictionary must be laid out as a set\n"
    append result "of files, with each file containing a list of words (in\n"
    append result "any order) all of the same length, one word per line.\n"
    append result "The filenames must start with the string <B>len</B> and\n"
    append result "end with a 2 digit number describing the length of the\n"
    append result "words inside the file.  For example, the file\n"
    append result "<B>len04</B> could contain:\n"
    append result "<P>\n"
    append result "<CODE>\n"
    append result "very<BR>\n"
    append result "that<BR>\n"
    append result "lean<BR>\n"
    append result "keys<BR>\n"
    append result "used<BR>\n"
    append result "type<BR>\n"
    append result "foot<BR>\n"
    append result "mine<BR>\n"
    append result "eery<BR>\n"
    append result "flee<BR>\n"
    append result "</CODE>\n"

    return $result
}
