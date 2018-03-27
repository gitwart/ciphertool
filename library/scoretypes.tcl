# scoretypes.tcl --
#
#	Some extra scoring types for testing.
#
# RCS: @(#) $Id: scoretypes.tcl,v 1.4 2008/03/01 17:08:24 wart Exp $
#
# Copyright (C) 2005  Mike Thomas <wart@kobold.org>
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

package require Scoredata
package provide Scoretypes 1.0

namespace eval Scoretypes {
    variable wordtreeCmd {}
    variable digramlogCmd {}
    variable trigramlogCmd {}
    variable tetragramlogCmd {}

    variable comboweight 0.5
}

# Scoretypes::tricomboscore
#
#	A custom scoring function that combines a trigramlog score with
#       a wordtree score.
#
# Arguments:
#
#	command		The subcommand to the scoring function.
#	args	        (optional) Any additional arguments to the custom
#                       scoring function.
#
# Result:
#	None.

proc Scoretypes::tricomboscore {command args} {
    variable wordtreeCmd
    variable trigramlogCmd
    variable comboweight

    if {$wordtreeCmd == ""} {
        set wordtreeCmd [score create wordtree]
        ::Scoredata::loadData $wordtreeCmd
    }
    if {$trigramlogCmd == ""} {
        set trigramlogCmd [score create trigramlog]
        ::Scoredata::loadData $trigramlogCmd
    }

    switch $command {
        type {
            return tricomboscore
        }
        elemvalue {
        }
        value {
            set plaintext $args
            set value [expr [$trigramlogCmd value $plaintext] + [$wordtreeCmd value $plaintext]*$comboweight]

            return $value
        }
        elemsize {
        }
        add {
        }
        normalize {
        }
        dump {
        }
    }
}

# Scoretypes::dicomboscore
#
#	A custom scoring function that combines a digramlog score with
#       a wordtree score.
#
# Arguments:
#
#	command		The subcommand to the scoring function.
#	args	        (optional) Any additional arguments to the custom
#                       scoring function.
#
# Result:
#	None.

proc Scoretypes::dicomboscore {command args} {
    variable wordtreeCmd
    variable digramlogCmd
    variable comboweight

    if {$wordtreeCmd == ""} {
        set wordtreeCmd [score create wordtree]
        ::Scoredata::loadData $wordtreeCmd
    }
    if {$digramlogCmd == ""} {
        set digramlogCmd [score create digramlog]
        ::Scoredata::loadData $digramlogCmd
    }

    switch $command {
        type {
            return dicomboscore
        }
        elemvalue {
        }
        value {
            set plaintext $args
            set value [expr [$digramlogCmd value $plaintext] + [$wordtreeCmd value $plaintext]*$comboweight]

            return $value
        }
        elemsize {
        }
        add {
        }
        normalize {
        }
        dump {
        }
    }
}

# Scoretypes::tetracomboscore
#
#	A custom scoring function that combines a 4-gramlog score with
#       a wordtree score.
#
# Arguments:
#
#	command		The subcommand to the scoring function.
#	args	        (optional) Any additional arguments to the custom
#                       scoring function.
#
# Result:
#	None.

proc Scoretypes::tetracomboscore {command args} {
    variable wordtreeCmd
    variable tetragramlogCmd
    variable comboweight

    if {$wordtreeCmd == ""} {
        set wordtreeCmd [score create wordtree]
        ::Scoredata::loadData $wordtreeCmd
    }
    if {$tetragramlogCmd == ""} {
        set tetragramlogCmd [score create ngramlog]
        $tetragramlogCmd elemsize 4
        ::Scoredata::loadData $tetragramlogCmd
        set comboweight 500
    }

    switch $command {
        type {
            return tetracomboscore
        }
        elemvalue {
        }
        value {
            set plaintext $args
            set value [expr [$tetragramlogCmd value $plaintext] + [$wordtreeCmd value $plaintext]*$comboweight]

            return $value
        }
        elemsize {
        }
        add {
        }
        normalize {
        }
        dump {
        }
    }
}
