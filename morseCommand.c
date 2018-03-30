/*
 * morseCommand.c --
 *
 *	This file implements the "morse" Tcl command for performing
 *	morse code <-> alphanumeric conversions.
 *
 *
 * Copyright (c) 2002-2004 Michael Thomas <wart@kobold.org>
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

#include <morse.h>
#include <morseCommand.h>

#include <cipherDebug.h>
#include <string.h>
#include <stdlib.h>

/*
 * Usage:  morse string
 */

int		MorseCmd(ClientData, Tcl_Interp *, int , const char **);

int
MorseCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    int         inputLength=0;
    int		convType = TOTEXT;
    const char	*inputString;
    char	*result=(char *)NULL;

    if (argc != 2) {
	Tcl_AppendResult(interp, "Usage:  ", *argv, " string", (char *)NULL);
	return TCL_ERROR;
    }

    argv++, argc--;
    inputString = *argv;
    inputLength = (int)strlen(inputString);
    argv++, argc--;

    /*
     * Determine if we are performing a morse -> text or a text -> morse
     * translation based on the characters in the input string.  The
     * iteration variable in this loop doubles as a counter for the length
     * of the input string.  Clever, eh?
     *
     * Assume we are converting to morse code unless we find a completely
     * valid string of morse characters that is longer than 1 character.
     */

    convType = TOMORSE;
    if (inputLength > 1 && MorseValid(inputString)) {
	convType = TOTEXT;
    }

    if (convType == TOTEXT) {
	/*
	 * Text translations from morse code are guaranteed to be shorter
	 * than the morse code string.  If we set our result to have
	 * the same length as the morese code string then we don't have
	 * to worry about any buffer overflow.
	 */
	result = (char *)ckalloc(sizeof(char) * inputLength + 1);
	MorseStringToString(inputString, result);

	Tcl_SetResult(interp, result, TCL_DYNAMIC);
    } else {
	Tcl_ResetResult(interp);
	/*
	 * result is created by malloc() in StringToMorse.
	 */
	result = StringToMorse(inputString);
	Tcl_SetResult(interp, result, TCL_VOLATILE);
	free(result);
    }

    return TCL_OK;
}
