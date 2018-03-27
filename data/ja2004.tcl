#!/bin/sh
# \
exec tclsh8.3 "$0" ${1+"$@"}

package require cipher
package require Crithm

proc Crithm::checkKey {} {

    if {[expr [crithm value ddr] * [crithm value ddr]] == [expr [crithm value dinner] - [crithm value eooi]]} {
    if {[expr [crithm value di] - [crithm value ie]] == [expr [crithm value ek]]} {
    if {[expr [crithm value eknn] - [crithm value ekve]] == [expr [crithm value no]]} {
    if {[expr [crithm value noer] - [crithm value mdto]] == [expr [crithm value eooi]]} {
        return 1
    }
    }
    }
    }

    return 0

}

Crithm::start deikmnortv

Crithm::saveSolution /home/wart/src/ciphers/ciphertool/data/ja2004.tcl.out
Crithm::saveSolution stdout
