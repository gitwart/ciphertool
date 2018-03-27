#!/usr/local/bin/tclsh

set k3key [lindex $argv 0]
if {[string length $k3key] != 26} {
    puts stderr "Key must be 26 characters.  Found [string length $k3key]"
    exit 1
}

for {set period 0} {$period < 26} {incr period} {
    set shiftedKey {}
    if {$period % 2 == 1} {
	for {set i 0} {$i < 26} {incr i} {
	    append shiftedKey [string index $k3key [expr {($i * $period) % 26}]]
	}
    } else {
	for {set i 0} {$i < 26} {incr i 2} {
	    append shiftedKey [string index $k3key [expr {($i * $period) % 26}]]
	}
	append shiftedKey { }
	for {set i 1} {$i < 26} {incr i 2} {
	    append shiftedKey [string index $k3key [expr {(($i * $period) + 1) % 26}]]
	}
    }
    puts "$period: $shiftedKey"
}
