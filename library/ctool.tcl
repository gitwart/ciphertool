# ctool.tcl --
#
#	Basic commands for the ctool gui.
#
# RCS: @(#) $Id: ctool.tcl,v 1.10 2008/03/16 23:59:01 wart Exp $
#
# Copyright (C) 1998-2004  Mike Thomas <wart@kobold.org>
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
package require CipherUtil 1.0

proc load_new_cipher {file type ciphervar} {
    upvar $ciphervar cipher

    if {[string match $file {}]} return

    waitcursor on
    set fileid [open $file r]

    set ctext {}
    while {![eof $fileid]} {
	gets $fileid line

	if {$ctext == ""} {
	    set ctext $line
	} else {
	    append ctext " $line"
	}
    }
    close $fileid

    string trim $ctext { }

    set cipher(ctext) $ctext
    set cipher(load_file) {}

    if {$type == {}} {
	while {[string match $cipher(type,new) {}]} {
	    get_cipher_type
	}
	set cipher(type) $cipher(type,new)
	set cipher(type,new) {}
    } else {
	set cipher(type) $type
    }

    show_toolbar

    set_bindings $cipher(type)

    waitcursor off

    wm title . $file
    create_cipher
}

proc show_toolbar {args} {
    waitcursor on

    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return

    if {![winfo exists .toolbar.$cipherinfo(type)]} {
	create_input_$cipherinfo(type) .toolbar.$cipherinfo(type) \
		.bbar.misc
    }
    foreach el [pack slaves .toolbar] {
	pack forget $el
    }
    pack .toolbar.$cipherinfo(type) -fill both -expand 1

    waitcursor off
}

proc set_bindings {args} {
    set ciphertype $args
    global cipherinfo

    # TODO:  Remove the old bindings.
    if {[info commands set_bindings_$ciphertype] != ""} {
	set_bindings_$ciphertype $cipherinfo(text)
    }
}

proc create_cipher {args} {
    waitcursor on

    global cipherinfo

    if {[catch {set cipherinfo(object) [cipher create $cipherinfo(type)\
	    -ciphertext $cipherinfo(ctext)]} errors]} {
	error $errors
    }

    create_histogram
    display_cipher

    waitcursor off
}

proc display_cipher {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    display_cipher_$cipherinfo(type)
    display_key_$cipherinfo(type) .stats.key

    waitcursor off
}

proc show_key {args} {
    global cipherinfo

    waitcursor on

    if {$cipherinfo(key,show)} {
	pack .stats.key -fill both -expand 1
    } else {
	pack forget .stats.key
	.stats configure -height 1
    }

    waitcursor off
}

proc clear_key {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    clear_key_$cipherinfo(type)

    waitcursor off
}

proc do_sub {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    do_sub_$cipherinfo(type)

    waitcursor off
}

proc solve_cipher {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    eval solve_cipher_$cipherinfo(type) $args
    display_pt_$cipherinfo(type)
    display_key_$cipherinfo(type) .stats.key

    waitcursor off
}

proc display_key {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    eval display_key_$cipherinfo(type) .stats.key $args

    waitcursor off
}

proc display_pt {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    eval display_pt_$cipherinfo(type) $args
    display_key_$cipherinfo(type) .stats.key

    waitcursor off
}

proc save_cipher {} {
    global cipherinfo

    if {[string match $cipherinfo(object) {}]} {
	tk_dialog .error "Save Error" "Can't save until a cipher has been loaded" info 0 Ok
    }

    # Prompt the user for a filename if this wasn't loaded from a file.

    if {[string match $cipherinfo(load_file) {}]} {
	set filename [tk_getSaveFile]
    } else {
	set filename $cipherinfo(load_file)
    }

    if {[string match $filename {}]} {
	return
    }

    set chanid [open $filename w]
    CipherUtil::writeCipherToFile $cipherinfo(object) $chanid
    if {[catch {
        package require Dictionary
        set Dictionary::cache [list word length]
        set pt [$cipherinfo(object) cget -pt]
        regsub -all { } $pt {} pt
        set readablePt [Dictionary::findWords $pt]
        puts $chanid "#plaintext=$readablePt"
    } msg]} {
        # Uncomment for debugging.
        #error $msg
    }
    close $chanid
    set cipherinfo(load_file) $filename
    wm title . $cipherinfo(load_file)
}

proc save_cipher_as {} {
    global cipherinfo

    if {[string match $cipherinfo(object) {}]} {
	tk_dialog .error "Save Error" "Can't save until a cipher has been loaded" info 0 Ok
    }

    # Prompt the user for a filename if this wasn't loaded from a file.

    set filename [tk_getSaveFile]

    if {[string match $filename {}]} {
	return
    }

    set chanid [open $filename w]
    CipherUtil::writeCipherToFile $cipherinfo(object) $chanid
    if {[catch {
        package require Dictionary
        set Dictionary::cache [list word length]
        set pt [$cipherinfo(object) cget -pt]
        regsub -all { } $pt {} pt
        set readablePt [Dictionary::findWords $pt]
        puts $chanid "#plaintext=$readablePt"
    } msg]} {
        # Uncomment for debugging.
        #error $msg
    }
    close $chanid
    set cipherinfo(load_file) $filename
    wm title . $cipherinfo(load_file)
}

proc load_saved_cipher {args} {
    global cipherinfo
    
    close_current_cipher

    set filename [lindex $args 0]

    if {[string match $filename {}]} return

    set cipherinfo(object) [CipherUtil::createCipherFromFile $filename]
    set cipherinfo(ctext) [$cipherinfo(object) cget -ctext]
    set cipherinfo(type) [$cipherinfo(object) cget -type]
    set cipherinfo(load_file) $filename

    show_toolbar

    set_bindings $cipherinfo(type)

    create_histogram
    display_cipher

    display_pt
    wm title . $filename
}

proc close_current_cipher {args} {
    global cipherinfo

    if {[catch {rename $cipherinfo(object) {}} msg]} {
	#puts stderr "Error deleting cipher:  $msg"
    }
}

proc locate_tip {} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    if {$cipherinfo(sub,ct) == ""} {
	set result [$cipherinfo(object) locate $cipherinfo(sub,pt)]
    } else {
	set result [$cipherinfo(object) locate $cipherinfo(sub,pt) $cipherinfo(sub,ct)]
    }
    #puts "Tip found at $result"

    display_pt

    waitcursor off
}

proc show_histogram {} {
    global cipherinfo

    if {$cipherinfo(hist,show)} {
	pack .stats.hist -fill both -expand 1
    } else {
	pack forget .stats.hist
	.stats configure -height 1
    }
}

proc create_histogram {} {
    global cipherinfo

    set c .stats.hist

    if {!$cipherinfo(hist,show)} { pack forget $c ; .stats configure -height 1 ; return }

    update

    set width [winfo width $c]
    set height [winfo height $c]

    set histogram [stat histogram $cipherinfo(ctext)]
    if {[info exists cipherinfo(hist)]} {
	set i 1
	foreach {el} $histogram {
	    set x [expr {double($i) / $l * $width}]
	    $c create text coords index_[lindex $el 0] $x [expr {$height-12}]

	    $c create coords bar_[lindex $el 0] [expr {$x - 5}]\
		    [expr {$height - 14}] [expr {$x + 5}]\
		    [expr {$height - 14 - 3*[lindex $el 1]}]
		    
	    $c create coords count_[lindex $el 0] $x [expr {$height-27}]

	    incr i
	}
    } else {
	set i 1
	set l [expr {[llength $histogram] + 1}]

	foreach {el} $histogram {
	    set x [expr {double($i) / $l * $width}]
	    $c create text $x [expr {$height-3}]\
		    -anchor s -text [string toupper [lindex $el 0]]\
		    -tags "index index_[lindex $el 0]"

	    $c create rectangle [expr {$x - 5}] [expr {$height - 18}]\
		    [expr {$x + 5}] [expr {$height - 18 - 3*[lindex $el 1]}]\
		    -fill pink -tags "bar bar_[lindex $el 0]"
		    
	    $c create text $x [expr {$height-20}]\
		    -anchor s -text [lindex $el 1]\
		    -tags "count count_[lindex $el 0]"

	    incr i
	}
    }
}

::tcl::OptProc set_cipher_type {
    {-type -string {} "Type of new cipher"}
} {
    Set_cipher_type $type
}

proc Set_cipher_type {type} {
    global cipherinfo

    if {[string match $type {}]} {
	get_cipher_type

	set type $cipherinfo(type,new)
    }

    return $type
}

proc get_cipher_type {} {
    global cipherinfo

    toplevel .type
    wm title .type "Select Cipher Type"

    set height [llength $cipherinfo(typelist)]

    label	.type.l -text "Select a Cipher Type"
    listbox	.type.list -height [expr {$height +1}]
    bind	.type.list <Double-Button-1> {
	set cipherinfo(type,new) [%W get [%W nearest %y]]
	destroy .type
    }

    foreach el $cipherinfo(typelist) {
	.type.list insert end $el
    }
    
    frame	.type.bbox
    button	.type.bbox.ok -text Ok -command {set cipherinfo(type,new) [.type.list get [.type.list curselection]] ; destroy .type}
    button	.type.bbox.cancel -text Cancel -command {set cipherinfo(type,new) $cipherinfo(type) ; destroy .type}

    pack .type.l
    pack .type.list
    pack .type.bbox
    pack .type.bbox.ok -side left
    pack .type.bbox.cancel -side left

    vwait cipherinfo(type,new)

#    wm title . "$cipherinfo(type,new) cipher"
}

proc set_period {args} {
    global cipherinfo

    if {[string match {} $cipherinfo(type)]} return
    if {[string match {} $cipherinfo(object)]} return

    waitcursor on

    $cipherinfo(object) configure -period $cipherinfo(sub,period)

    display_cipher
    display_pt
    display_key

    waitcursor off
}

proc print_workspace {} {
    global cipherinfo

    set printerid [open "|lpr" w]

    if {$cipherinfo(key,show)} {
	set text [.stats.key get 0.0 end]

	puts $printerid $text
	puts $printerid ""
    }

    set text [$cipherinfo(text) get 0.0 end]
    puts $printerid $text

    close $printerid
}

proc waitcursor {state} {
    if {[string match $state on]} {
	. configure -cursor watch
    } else {
	. configure -cursor {}
    }
    update idletasks
}
