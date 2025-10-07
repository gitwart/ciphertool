# cipherIdentify.tcl --
#
#	This file implements rule-based cipher type identification
#	using statistical features extracted from ciphertext.
#
# Copyright (c) 2025
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

package provide CipherIdentify 1.0

namespace eval CipherIdentify {
    namespace export classifyByRules findBestPeriod

    # IoC thresholds for classification
    variable IOC_MONOALPHABETIC 0.060  ;# Typical for monoalphabetic substitution
    variable IOC_POLYALPHABETIC 0.045  ;# Typical for polyalphabetic ciphers
    variable IOC_TRANSPOSITION 0.065   ;# Close to plaintext
}

#
# CipherIdentify::classifyByRules --
#
#	Classify cipher type based on extracted features using
#	rule-based heuristics.
#
# Arguments:
#	features	Dictionary of features from 'identify features'
#
# Results:
#	Returns a list of {type confidence ?params?} tuples, sorted
#	by confidence (highest first).
#

proc CipherIdentify::classifyByRules {features} {
    variable IOC_MONOALPHABETIC
    variable IOC_POLYALPHABETIC
    variable IOC_TRANSPOSITION

    set candidates {}

    # Extract key features
    set ioc [dict get $features ioc]
    set length [dict get $features length]
    set distinctChars [dict get $features distinctChars]
    set entropy [dict get $features entropy]
    set periodicIoc [dict get $features periodicIoc]

    # Rule 1: High IoC suggests monoalphabetic substitution or transposition
    if {$ioc >= $IOC_MONOALPHABETIC} {
        # Check if it's transposition (IoC very close to English)
        if {$ioc >= $IOC_TRANSPOSITION} {
            lappend candidates [list columnar 0.75 {}]
            lappend candidates [list route 0.70 {}]
            lappend candidates [list railfence 0.65 {}]
        }

        # Standard monoalphabetic substitution
        lappend candidates [list aristocrat 0.85 {}]
        lappend candidates [list caesar 0.50 {}]
    }

    # Rule 2: Low IoC suggests polyalphabetic cipher
    if {$ioc < $IOC_POLYALPHABETIC} {
        # Try to find period using periodic IoC
        set period [findBestPeriod $periodicIoc]

        if {$period > 0} {
            lappend candidates [list vigenere 0.80 [list period $period]]
            lappend candidates [list beaufort 0.70 [list period $period]]
            lappend candidates [list porta 0.65 [list period $period]]
        } else {
            # No clear period found
            lappend candidates [list vigenere 0.60 {}]
            lappend candidates [list beaufort 0.50 {}]
        }

        # Could also be a fractionating cipher
        lappend candidates [list bifid 0.55 {}]
        lappend candidates [list trifid 0.45 {}]
    }

    # Rule 3: Medium IoC - could be several types
    if {$ioc >= $IOC_POLYALPHABETIC && $ioc < $IOC_MONOALPHABETIC} {
        # Check for specific patterns
        set period [findBestPeriod $periodicIoc]

        if {$period > 0} {
            lappend candidates [list vigenere 0.70 [list period $period]]
            lappend candidates [list beaufort 0.60 [list period $period]]
        }

        lappend candidates [list playfair 0.65 {}]
        lappend candidates [list foursquare 0.55 {}]
        lappend candidates [list bifid 0.60 {}]
    }

    # Rule 4: Very short text - harder to classify
    if {$length < 50} {
        # Reduce confidence for all candidates
        set newCandidates {}
        foreach candidate $candidates {
            lassign $candidate type conf params
            lappend newCandidates [list $type [expr {$conf * 0.7}] $params]
        }
        set candidates $newCandidates
    }

    # Sort by confidence (descending)
    set candidates [lsort -real -decreasing -index 1 $candidates]

    return $candidates
}

#
# CipherIdentify::findBestPeriod --
#
#	Analyze periodic IoC values to find the most likely period
#	for a polyalphabetic cipher.
#
# Arguments:
#	periodicIocList	List of periodic IoC values for periods 2-20
#
# Results:
#	Returns the best period (2-20), or 0 if no clear period found.
#

proc CipherIdentify::findBestPeriod {periodicIocList} {
    variable IOC_MONOALPHABETIC

    set bestPeriod 0
    set maxIoc 0.0
    set period 2

    foreach ioc $periodicIocList {
        # Look for periods where IoC spikes (indicates correct period)
        if {$ioc > $maxIoc && $ioc >= $IOC_MONOALPHABETIC} {
            set maxIoc $ioc
            set bestPeriod $period
        }
        incr period
    }

    return $bestPeriod
}

#
# CipherIdentify::identifyCipher --
#
#	High-level convenience function to identify cipher type.
#
# Arguments:
#	ciphertext	The ciphertext to analyze
#	options		Optional: -threshold <value>, -return <all|best>
#
# Results:
#	Returns identification results based on options.
#

proc CipherIdentify::identifyCipher {ciphertext args} {
    # Parse options
    set threshold 0.5
    set returnMode "best"

    foreach {opt val} $args {
        switch -- $opt {
            -threshold { set threshold $val }
            -return { set returnMode $val }
            default {
                error "Unknown option: $opt"
            }
        }
    }

    # Extract features
    set features [identify features $ciphertext]

    # Classify
    set candidates [classifyByRules $features]

    # Filter by threshold
    set filtered {}
    foreach candidate $candidates {
        lassign $candidate type conf params
        if {$conf >= $threshold} {
            lappend filtered $candidate
        }
    }

    # Return based on mode
    if {$returnMode eq "best"} {
        if {[llength $filtered] > 0} {
            return [lindex $filtered 0]
        } else {
            return {}
        }
    } else {
        return $filtered
    }
}
