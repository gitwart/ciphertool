#!/bin/sh
# \
exec tclsh "$0" ${1+"$@"}

package require Dictionary

set Dictionary::directory $env(HOME)/share/dict

set infile [lindex $argv 0]
set infileId [open $infile r]

set wordList {}
while {![eof $infileId]} {
    gets $infileId word
    lappend wordList $word
}
close $infileId

set totalAdded 0
foreach word $wordList {
    incr totalAdded [Dictionary::addWord $word]
    puts "$word"
}

puts "$totalAdded words added"
