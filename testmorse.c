/*
 * testmorse.c --
 *
 *	This program tests the mosrse code routines in morse.c.  It
 *	reads morse code from stdin and writes the plaintext to stdout.
 *
 * Copyright (c) 1998-2000 Michael Thomas <wart@kobold.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include <stdio.h>
#include <morse.h>

int
main(int argc, char **argv)
{
    char tempStr[128];
    char tempStr2[128];
    char *c;

    while(1) {
	gets(tempStr);

	if (tempStr[0] == (char)NULL)
	    exit(0);

	if (MorseStringToString(tempStr, tempStr2)) {
	    fprintf(stdout, "%s (%d)\n", tempStr2, MorseValid(tempStr));
	} else {
	    fprintf(stdout, "Bad input\n");
	}
	fflush(stdout);
    }

    exit(0);
}
