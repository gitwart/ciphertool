# beaufort.tcl --
#
#	Display routines for the beaufort cipher type.
#
# RCS: @(#) $Id: beaufort.tcl,v 1.2 2004/09/08 17:05:00 wart Exp $
#
# Copyright (C) 1998-2000  Mike Thomas <wart@kobold.org>
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

proc display_cipher_beaufort {args} {
    eval display_cipher_vigenere $args
}

proc clear_key_beaufort {args} {
    eval clear_key_vigenere $args
}

proc do_sub_beaufort {args} {
    eval do_sub_vigenere $args
}

proc display_pt_beaufort {args} {
    eval display_pt_vigenere $args
}

proc display_key_beaufort {w args} {
    global cipherinfo

    set key [lindex [$cipherinfo(object) cget -key] 1]
    eval display_key_vigenere $w "$key" $args
}

proc create_input_beaufort {w args} {
    eval create_input_vigenere $w $args
}

proc solve_cipher_beaufort {args} {
    eval solve_cipher_vigenere $args
}

proc save_cipher_beaufort {chanid} {
}
