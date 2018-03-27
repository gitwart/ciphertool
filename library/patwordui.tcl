# patwordui.tcl --
#
#	Library routines for patristocrat brute force word searching user
#	interface.
#
# RCS: @(#) $Id: patwordui.tcl,v 1.6 2004/09/08 17:05:00 wart Exp $
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

package provide PatWordUI 1.0

namespace eval PatwordUI {
    variable panelFrame
    variable panelCount 0
    variable panels
    variable canvas
    variable wordlistWinHeight 25

    variable blankWord "---"
    variable blankProgress "-- of --"
    variable blank ""

    variable iteration 0

    variable pauseVar 0

    variable solutions {}
    set bestResult {}
    set bestPt {}
    set bestValue 0

    set skipLevel 0
}

# PatwordUI::createPanel
#
#	Create a new panel for showing another level deep in the
#	list of patristocrat words.
#
# Arguments:
#
#	parent		The parent frame in which this panel will be created.
#
# Side effects:
#	Three more rows are added to the end of the parent's grid layout.
#
# Result:
#	Returns the parent input argument.

proc PatwordUI::createPanel {parent} {
    variable panels
    variable panelCount
    variable wordlistWinHeight
    set index $panelCount

    set panels($index,visible) 1
#    set panels($panelCount,win) [frame $parent.panel$panelCount]
    set p $parent
    set panels($index,progress) "0 of 0"
    set panels($index,word) ""
    set panels($index,wordlist) ""

    frame $p.buffer$index -height 10 -bg #888888
    set panels($index,toggleWin) [button $p.toggle$index -text "-" \
	    -command [list PatwordUI::togglePanel $index] \
	    -padx 4 -pady 0]
    set panels($index,wordWin) [label $p.word$index \
	    -textvariable PatwordUI::panels($index,word) \
	    -font fixed \
	    -relief flat]
    set panels($index,progressWin) [button $p.next$index \
	    -textvariable PatwordUI::panels($index,progress) \
	    -command [list PatwordUI::showWordlist $index]]
    set panels($index,nextWin) [button $p.progress$index \
	    -text Next \
	    -command [list PatwordUI::showNextWord $index] \
	    -state normal]
    set panels($index,keyWin) [label $p.key$index \
	    -textvariable PatwordUI::panels($index,key) \
	    -font fixed \
	    -relief ridge]
    set panels($index,ptWin) [label $p.pt$index \
	    -textvariable PatwordUI::panels($index,pt) \
	    -font fixed \
	    -relief ridge]

    set panels($index,wordlistWin) {}
    set panels($index,wordlistWin,visible) 0

#    grid $panels($panelCount,win)

    grid $p.buffer$index -columnspan 4 -sticky we
    grid $panels($index,toggleWin) \
	    $panels($index,wordWin) \
	    $panels($index,progressWin) \
	    $panels($index,nextWin)
    grid $panels($index,keyWin) -columnspan 2 -column 2 -sticky we
    grid $panels($index,ptWin) -columnspan 4 -sticky we
    
    grid configure $panels($index,toggleWin) -sticky nw
    grid configure $panels($index,progressWin) -sticky we
    grid configure $panels($index,nextWin) -sticky e

    incr panelCount

    if {[info exists panels([expr {$index-1}],visible)]} {
	PatwordUI::togglePanel $index $panels([expr {$index-1}],visible)
    }

    tkwait visibility $panels($index,ptWin)
    updateScrollRegion

    return $p
}

# PatwordUI::togglePanel
#
#	Create a new panel for showing another level deep in the
#	list of patristocrat words.
#
# Arguments:
#
#	index		The panel number whose state will be toggled.
#	visible		Optional argument indicating the new state.  If
#			not specified then the panel's current state will
#			be changed.
#
# Side effects:
#	If the panel is made visible, then all earlier panels also become
#	visible.  If hidden, then all later panels also become hidden.
#
# Result:
#	None.

proc PatwordUI::togglePanel {index {visible {}}} {
    variable panelCount
    variable panels

    if {$index >= $panelCount || $index < 0} {
	return
    }

    if {$visible == ""} {
	if {$panels($index,visible)} {
	    set newState 0
	} else {
	    set newState 1
	}
    } else {
	set newState $visible
    }

    if {$newState == $panels($index,visible)} {
	return
    }

    if {$newState} {
	set panels($index,visible) 1
	$panels($index,progressWin) configure \
		-textvariable PatwordUI::panels($index,progress) \
		-state normal
	$panels($index,wordWin) configure \
		-textvariable PatwordUI::panels($index,word) \
		-state normal
	$panels($index,nextWin) configure \
		-state normal
	$panels($index,toggleWin) configure -text "-"
	$panels($index,keyWin) configure -textvariable "PatwordUI::panels($index,key)"
	$panels($index,ptWin) configure -textvariable "PatwordUI::panels($index,pt)"
	incr index -1
	togglePanel $index 1
    } else {
	set panels($index,visible) 0
	$panels($index,progressWin) configure \
		-textvariable PatwordUI::blankProgress \
		-state disabled
	$panels($index,wordWin) configure \
		-textvariable PatwordUI::blankWord \
		-state disabled
	$panels($index,nextWin) configure \
		-state disabled
	$panels($index,toggleWin) configure -text "+"
	$panels($index,keyWin) configure -textvariable "PatwordUI::blank"
	$panels($index,ptWin) configure -textvariable "PatwordUI::blank"
	incr index 1
	togglePanel $index 0
    }
}

# PatwordUI::clearPanel
#
#	Clear the contents of the panel, including all state information
#	such as the word list, plaintext, etc.
#
# Arguments:
#
#	index		The panel number whose state will be cleared.
#
# Side effects:
#	The word and progress display for this panel get set to default
#	empty values.
#
# Result:
#	None.

proc PatwordUI::clearPanel {index} {
    variable panels
    variable blankWord
    variable blankProgress

    set panels($index,word) $blankWord
    set panels($index,progress) $blankProgress
    set panels($index,wordlist) {}
    set panels($index,pt) {}
    set panels($index,key) {}
}

# PatwordUI::showIter
#
#	Update the Ui to reflect a change in the search progress.
#
# Arguments:
#
#	cipherObj	The cipher object containing the key and solution.
#	count		The number of iterations already attempted.
#	result		The list of words in the current solution.
#	word		The current word being attempted.
#	wordList	The set of all words in the current loop.
#
# Side effects:
#	The UI is updated to reflect the new search progress.
#	empty values.  'update' is called to process any pending
#	UI requests.
#
# Result:
#	The number of levels to break out of in order to continue on to
#	the next word in an earlier list.  If '0' is returned then the
#	current list is still used.


proc PatwordUI::showIter {cipherObj count result word wordList} {
    variable panelCount
    variable panels
    variable panelFrame
    variable skipLevel

    set skipLevel -1
    set index [llength $result]

    if {$index >= $panelCount} {
	for {set i $panelCount} {$i <= $index} {incr i} {
	    set newPanel [createPanel $panelFrame]
	}
    }

    for {set i [expr {$index + 1}]} {$i < $panelCount} {incr i} {
	clearPanel $i
    }

    set panels($index,wordlist) $wordList
    set panels($index,pt) [$cipherObj cget -pt]
    set panels($index,word) $word
    set panels($index,key) [lindex [$cipherObj cget -key] 1]
    set panels($index,progress) "[expr {[lsearch $wordList $word]+1}] of [llength $wordList]"
    if {[winfo exists $panels($index,wordlistWin)] \
	    && $panels($index,wordlistWin,visible)} {
	$panels($index,wordlistWin).list selection clear 0 end
	$panels($index,wordlistWin).list selection set [lsearch $wordList $word]
	$panels($index,wordlistWin).list see [lsearch $wordList $word]
    }

    if {$skipLevel == "restart"} {
	for {set i 0} {$i < $panelCount} {incr i} {
	    clearPanel $i
	}
    }

    update
    return $skipLevel
}

# PatwordUI::showBest
#
#	Update the Ui to reflect a new best fit.
#
# Arguments:
#
#	cipherObj	The cipher object containing the key and solution.
#	count		The number of iterations already attempted.
#	result		The list of words in the current solution.
#	word		The current word being attempted.
#	wordList	The set of all words in the current loop.
#
# Side effects:
#	The UI is updated to reflect the new best solution.
#
# Result:
#	None.

proc PatwordUI::showBest {cipherObj count result word wordList} {
    variable bestResult
    variable bestPt
    variable bestValue
    variable solutions

    lappend solutions [list [concat $result $word] [$cipherObj cget -pt]]

    set value 0
    foreach w [concat $result $word] {
	if {[string length $w] > 2} {
	    set value [expr {$value + [string length $w]*[string length $w]}]
	}
    }
    if {$value > $bestValue} {
	set bestValue $value
	set bestResult [concat $result $word]
	set bestPt [$cipherObj cget -pt]

	puts "#$bestResult"
	puts "#$bestPt"
    }

    update
}

proc PatwordUI::showSolutions {} {
    variable solutions

    toplevel .solutions
    text .solutions.text -width 80 -height 25 \
	    -xscrollcommand [list .solutions.hscroll set] \
	    -yscrollcommand [list .solutions.vscroll set] \
	    -wrap none \
	    -bg white
    scrollbar .solutions.vscroll \
	    -orient vertical \
	    -command [list .solutions.text yview]
    scrollbar .solutions.hscroll \
	    -orient horizontal \
	    -command [list .solutions.text xview]

    grid .solutions.text .solutions.vscroll
    grid .solutions.hscroll -sticky we
    grid configure .solutions.text -sticky news
    grid configure .solutions.vscroll -sticky ns
    grid columnconfigure .solutions 0 -weight 1
    grid rowconfigure .solutions 0 -weight 1

    foreach {pair} $solutions {
	set ptsplit [lindex $pair 0]
	set ptnosplit [lindex $pair 1]

	.solutions.text insert end $ptsplit\n
	.solutions.text insert end $ptnosplit\n
	.solutions.text insert end \n
    }
}

# PatwordUI::createUI
#
#	Create the top level user interface.
#
# Arguments:
#
#	topWin		The name of the window in which to create the ui.
#
# Side effects:
#	New windows are mapped to the screen.
#
# Result:
#	None.

proc PatwordUI::createUI {topWin} {
    variable panelFrame
    variable canvas
    variable wid

    frame $topWin.menubar
    frame $topWin.bottomFrame -height 300
    set canvas [canvas $topWin.bottomFrame.canvas -width 10 -height 10 \
	    -yscrollcommand [list $topWin.bottomFrame.vscroll set]]
    scrollbar $topWin.bottomFrame.vscroll \
	    -command [list $topWin.bottomFrame.canvas yview]

    set panelFrame [frame $topWin.bottomFrame.canvas.panelFrame -bd 0]
    $topWin.bottomFrame.canvas create window 0 0 -anchor nw -window $panelFrame

    button $topWin.menubar.exit -command exit -text "Exit"
    button $topWin.menubar.pause \
	    -text "Pause" \
	    -command [list PatwordUI::pause $topWin.menubar]
    button $topWin.menubar.go \
	    -text "Continue" \
	    -state disabled \
	    -command [list PatwordUI::unpause $topWin.menubar]
    button $topWin.menubar.view -command "PatwordUI::showSolutions" \
	    -text "Solutions..."
    button $topWin.menubar.clear -command "Dictionary::clearCache" \
	    -text "Clear Cache"
    button $topWin.menubar.restart -command "PatwordUI::restartUI" \
	    -text "Restart" \
	    -state active
#    button $topWin.menubar.memdump -command "memory active mem.dump" \
#	    -text "Memory dump" \
#	    -state active
    set wid(bestResult) [label $topWin.bestResult \
	    -justify left \
	    -textvariable PatwordUI::bestResult]
    set wid(bestPt) [label $topWin.bestPt \
	    -justify left \
	    -textvariable PatwordUI::bestPt]
    frame $topWin.filler -height 10 -bg #444444

    pack $topWin.bottomFrame.canvas -side left -fill both -expand true
    pack $topWin.bottomFrame.vscroll -side right -fill y
    grid $topWin.menubar.exit $topWin.menubar.pause $topWin.menubar.go \
	    $topWin.menubar.view $topWin.menubar.clear $topWin.menubar.restart
    grid $topWin.menubar
    grid $topWin.bestResult -sticky w -columnspan 4
    grid $topWin.bestPt -sticky w -columnspan 4
    grid $topWin.filler -sticky we -columnspan 4
    grid $topWin.bottomFrame -sticky news
#    grid $panelFrame

    if {$topWin == ""} {
	grid rowconfigure . 4 -weight 1
	grid columnconfigure . 0 -weight 1
    } else {
	grid rowconfigure $topWin 4 -weight 1
	grid columnconfigure $topWin 0 -weight 1
    }
    grid columnconfigure $topWin.bottomFrame 0 -weight 1
    grid columnconfigure $topWin.bottomFrame 1 -weight 0
    grid columnconfigure $panelFrame 0 -weight 0
    grid columnconfigure $panelFrame 2 -weight 0
    grid columnconfigure $panelFrame 3 -weight 0
}

proc PatwordUI::updateScrollRegion {} {
    variable canvas
    variable panelFrame

    set bbox [grid bbox $panelFrame 0 0]
    set width [winfo reqwidth $panelFrame]
    set height [winfo reqheight $panelFrame]
    $canvas configure -scrollregion "0 0 $width $height"
    $canvas configure -width $width -height $height
}

# PatwordUI::pause
#
#	Pause the word searching.
#
# Arguments:
#
#	wid		The frame containing the pause and continue buttons.
#
# Side effects:
#	The state of the pause/continue buttons is changed.
#
# Result:
#	None.

proc PatwordUI::pause {wid} {
    $wid.pause configure -state disabled
    $wid.go configure -state normal

    update

    vwait PatwordUI::pauseVar
}

# PatwordUI::unpause
#
#	Resume the word searching.
#
# Arguments:
#
#	wid		The frame containing the pause and continue buttons.
#
# Side effects:
#	The state of the pause/continue buttons is changed.
#
# Result:
#	None.

proc PatwordUI::unpause {wid} {
    $wid.pause configure -state normal
    $wid.go configure -state disabled

    update

    incr PatwordUI::pauseVar
}

# PatwordUI::showWordList
#
#	Show the list of words in the current loop.
#
# Arguments:
#
#	index		The panel number whose word list will be displayed.
#
# Side effects:
#	A new toplevel window is created and mapped to the display.
#
# Result:
#	None.

proc PatwordUI::showWordlist {index} {
    variable panels
    variable wordlistWinHeight

    if {$panels($index,wordlistWin) == {} \
	    || ![winfo exists $panels($index,wordlistWin)]} {
	set panels($index,wordlistWin) [toplevel .panel$index]
	listbox $panels($index,wordlistWin).list \
		-height $wordlistWinHeight -width 25 \
		-listvar PatwordUI::panels($index,wordlist) \
		-yscrollcommand [list $panels($index,wordlistWin).vert set] \
		-selectmode single \
		-exportselection no \
		-font fixed
	
	scrollbar $panels($index,wordlistWin).vert \
		-command [list $panels($index,wordlistWin).list yview]

	grid $panels($index,wordlistWin).list \
		$panels($index,wordlistWin).vert -sticky ns
	grid configure $panels($index,wordlistWin).list -sticky news
	grid columnconfigure $panels($index,wordlistWin) 0 -weight 1
	grid rowconfigure $panels($index,wordlistWin) 0 -weight 1
    }
    set listWin $panels($index,wordlistWin)
    set panels($index,wordlistWin,visible) 1
    $listWin.list selection clear 0 end
    set wordIndex [lsearch $panels($index,wordlist) $panels($index,word)]
    $listWin.list selection set $wordIndex
    $listWin.list see $wordIndex
    wm deiconify $listWin
    raise $listWin
}

proc PatwordUI::showNextWord {index} {
    variable skipLevel

    set skipLevel $index
}

proc PatwordUI::restartUI {} {
    variable skipLevel

    set skipLevel "restart"
}
