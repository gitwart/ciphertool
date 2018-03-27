# crithm_gui.tcl --
#
#	Display routines for tkcrithm.
#
# RCS: @(#) $Id: crithm_gui.tcl,v 1.10 2005/11/08 22:13:50 wart Exp $
#
# Copyright (C) 2000-2002  Mike Thomas <wart@kobold.org>
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

package provide Crithm_gui 1.0

namespace eval Gui {
    variable window
    variable solutionList {}
    # Name of the file where the cipher was saved.  This is not the
    # file where the solution was saved.
    variable saveFile {}

    array set window {
	display {}
	solutionText {}
    }
}

proc Gui::createGui {} {
    variable window

    set topFrame [frame .t]

    frame $topFrame.menu -relief raised -borderwidth 2
    Gui::createMenu $topFrame.menu

    frame $topFrame.parmdisp
    Gui::createParameterDisplay $topFrame.parmdisp

    frame $topFrame.inputs -relief ridge -borderwidth 2
    Gui::createInputs $topFrame.inputs

    frame $topFrame.display
    frame $topFrame.display.left
    frame $topFrame.display.right
    set window(display) [createConstraintListbox $topFrame.display.left]
    Gui::createOutput $topFrame.display.right

    grid $topFrame.menu -row 0 -column 0 -sticky news
    grid $topFrame.parmdisp -row 1 -column 0 -sticky news
    grid $topFrame.inputs -row 2 -column 0 -sticky news
    grid $topFrame.display -row 3 -column 0 -sticky news

    grid $topFrame.display.left -row 0 -column 0 -sticky news
    grid $topFrame.display.right -row 0 -column 1 -sticky news

    grid rowconfigure $topFrame.display 0 -weight 1
    grid columnconfigure $topFrame.display 0 -weight 1
    grid columnconfigure $topFrame.display 1 -weight 1

    grid rowconfigure $topFrame 0 -weight 0
    grid rowconfigure $topFrame 1 -weight 0
    grid rowconfigure $topFrame 2 -weight 1
    grid rowconfigure $topFrame 3 -weight 0
    grid columnconfigure $topFrame 0 -weight 1
    grid columnconfigure $topFrame 0 -weight 1

    pack $topFrame -fill both -expand 1

    return
}

proc Gui::createOutput {topFrame} {
    variable window

    set window(solutionText) [text $topFrame.text \
	    -xscrollcommand "$topFrame.hsb set" \
	    -yscrollcommand "$topFrame.vsb set" \
	    -width 40]
    scrollbar $topFrame.vsb -command "$topFrame.text yview" -orient vert
    scrollbar $topFrame.hsb -command "$topFrame.text xview" -orient horiz
    label $topFrame.progress -textvariable parms(progress)

    grid $topFrame.text -row 0 -column 0 -sticky news
    grid $topFrame.vsb -row 0 -column 1 -sticky ns
    grid $topFrame.hsb -row 1 -column 0 -sticky we
    grid $topFrame.progress -row 2 -column 0 -columnspan 2 -sticky we

    grid columnconfigure $topFrame 0 -weight 1
    grid rowconfigure $topFrame 0 -weight 1

    return
}

proc Gui::createParameterDisplay {topFrame} {
    frame $topFrame.baseframe
    label $topFrame.baseframe.base -text "Base: "
    label $topFrame.baseframe.baseval -textvariable parms(base) \
	    -font fixed
    frame $topFrame.baseframe.spacer
    frame $topFrame.listframe
    label $topFrame.listframe.list -text "Letters: "
    label $topFrame.listframe.listval -textvariable parms(letterList) \
	    -font fixed
    frame $topFrame.listframe.spacer

    grid $topFrame.baseframe -row 0 -column 0 -sticky w
    grid $topFrame.baseframe.base -row 0 -column 0 -sticky w
    grid $topFrame.baseframe.baseval -row 0 -column 1 -sticky w
    grid $topFrame.baseframe.spacer -row 0 -column 2 -sticky w
    grid $topFrame.listframe -row 0 -column 1 -sticky w
    grid $topFrame.listframe.list -row 0 -column 0 -sticky w
    grid $topFrame.listframe.listval -row 0 -column 1 -sticky w
    grid $topFrame.listframe.spacer -row 0 -column 2 -sticky w

    grid columnconfigure $topFrame.baseframe 2 -weight 1
    grid columnconfigure $topFrame.listframe 2 -weight 1

    grid columnconfigure $topFrame 0 -weight 1
    grid columnconfigure $topFrame 1 -weight 1

    return
}

proc Gui::createDisplay {topFrame} {
    entry $topFrame.t -textvariable parms(equation)
    entry $topFrame.c -textvariable parms(code)

    grid $topFrame.t -sticky news -row 0 -column 0
    grid $topFrame.c -sticky news -row 1 -column 0
    grid columnconfigure $topFrame 0 -weight 1

    return $topFrame.t
}

proc Gui::createInputs {topFrame} {
    global parms

    entry $topFrame.lhs1 -textvariable parms(lhs1)
    set lhsOpWin [Gui::createOpSelector $topFrame.lhsop parms(lhsop)]
    entry $topFrame.lhs2 -textvariable parms(lhs2)
    label $topFrame.equal -text {==}
    entry $topFrame.rhs1 -textvariable parms(rhs1)
    set rhsOpWin [Gui::createOpSelector $topFrame.rhsop parms(rhsop)]
    $rhsOpWin configure -textvariable parms(rhsop)
    entry $topFrame.rhs2 -textvariable parms(rhs2)
    button $topFrame.addbutton -text "Add" -command "addConstraints"

    # Custom bindings for the equation input area.
    set bindBodyEntryLeft "focus $lhsOpWin
    	\[$lhsOpWin cget -menu\] invoke \\\\%A
	focus $topFrame.lhs2
	$topFrame.lhs2 selection range 0 end
	break"
    set bindBodyEntryRight "focus $rhsOpWin
    	\[$rhsOpWin cget -menu\] invoke \\\\%A
	focus $topFrame.rhs2
	$topFrame.rhs2 selection range 0 end
	break"
    set bindBodyMenu  "\[%W cget -menu\] invoke \\\\%A"

    foreach keysym [list plus minus slash asterisk asciicircum] {
	bind $topFrame.lhs1 <Key-$keysym> $bindBodyEntryLeft
	bind $topFrame.rhs1 <Key-$keysym> $bindBodyEntryRight
	bind $lhsOpWin      <Key-$keysym> $bindBodyMenu
	bind $rhsOpWin      <Key-$keysym> $bindBodyMenu
    }
    bind $topFrame.rhs1 <Key-Return> "
	[$rhsOpWin cget -menu] invoke {}
	set parms(rhs2) {}
	addConstraints
	focus $topFrame.lhs1
	$topFrame.lhs1 selection range 0 end
    "
    bind $topFrame.lhs2 <Key-equal> "
	focus $topFrame.rhs1
	$topFrame.rhs1 selection range 0 end
	break
    "
    bind $topFrame.rhs2 <Key-Return> "
	addConstraints
	focus $topFrame.lhs1
	$topFrame.lhs1 selection range 0 end
	break
    "

    grid $topFrame.lhs1 -row 0 -column 1
    grid $lhsOpWin -row 0 -column 2
    grid $topFrame.lhs2 -row 0 -column 3
    grid $topFrame.equal -row 0 -column 4
    grid $topFrame.rhs1 -row 0 -column 5
    grid $rhsOpWin -row 0 -column 6
    grid $topFrame.rhs2 -row 0 -column 7
    grid $topFrame.addbutton -row 0 -column 8

    grid configure $topFrame -ipady 10

    return
}

proc Gui::createConstraintListbox {topFrame} {
    listbox $topFrame.list -width 40 -listvar parms(equationList) \
	    -yscrollcommand "$topFrame.vsb set"
    scrollbar $topFrame.vsb -orient vertical -command "$topFrame.list yview"

    bind $topFrame.list <Button-3> {removeConstraint [%W nearest %y]}

    grid $topFrame.list -row 0 -column 0 -sticky news
    grid $topFrame.vsb -row 0 -column 1 -sticky ns

    grid columnconfigure $topFrame 0 -weight 1
    grid rowconfigure $topFrame 0 -weight 1
}

proc Gui::createOpSelector {menuPath textVar} {
    menubutton $menuPath -textvariable $textVar \
	    -indicatoron 1 -menu $menuPath.menu -relief raised \
	    -borderwidth 2 -takefocus 1 -highlightthickness 2
    menu $menuPath.menu -tearoff 0
    $menuPath.menu add command \
	    -command "set $textVar {}" \
	    -label {}
    $menuPath.menu add command \
	    -command "set $textVar +" \
	    -label +
    $menuPath.menu add command \
	    -command "set $textVar -" \
	    -label -
    $menuPath.menu add command \
	    -command "set $textVar *" \
	    -label *
    $menuPath.menu add command \
	    -command "set $textVar /" \
	    -label /
    $menuPath.menu add command \
	    -command "set $textVar ^" \
	    -label ^

    return $menuPath
}

proc Gui::createMenu {topFrame} {
    menubutton $topFrame.file -text File -menu $topFrame.file.menu
    menu $topFrame.file.menu -tearoff 0
    $topFrame.file.menu add command -label Show -command Gui::showConstraints
    $topFrame.file.menu add command -label "Save Puzzle..." \
	    -command Gui::saveConstraints
    $topFrame.file.menu add command -label "Save Solution..." \
	    -command Gui::saveSolution
    $topFrame.file.menu add command -label Solve -command doSolve
    $topFrame.file.menu add command -label Stop -command doStop
    $topFrame.file.menu add command -label Exit -command exit

    grid $topFrame.file -row 0 -column 0 -sticky w
    grid columnconfigure $topFrame 0 -weight 1

    return
}

proc Gui::showConstraints {} {
    variable window
    global parms

    $window(solutionText) delete 0.0 end
    $window(solutionText) insert end "proc Crithm::checkKey \{\} \{"
    $window(solutionText) insert end \
	    [Crithm::createCheckKeyProc $parms(constraintList)]
    $window(solutionText) insert end "\}"

    return
}

proc Gui::saveConstraints {} {
    global parms

    set outFile [tk_getSaveFile -defaultextension .tcl \
	    -title "Save to file..."]

    if {![string equal $outFile {}]} {
	set Gui::saveFile $outFile
	Crithm::saveCipherFile $outFile \
	    	[Crithm::getUniqueLetters $parms(equationList)] \
		$parms(constraintList)

	wm title . $outFile
    }
}

proc Gui::saveSolution {} {
    global parms
    set initialFile {}

    if {$Gui::saveFile != ""} {
	set initialFile ${Gui::saveFile}.sol
    }
    set outFile [tk_getSaveFile -defaultextension .sol \
	    -title "Save to file..." -initialfile $initialFile]

    if {![string equal $outFile {}]} {
	# We are assuming that the Crithm package is storing the solutions.
	Crithm::saveSolution $outFile
    }
}
