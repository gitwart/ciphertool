/*
 * morse.h --
 *
 *	This is the header file for the morse utility routines.
 *
 * Copyright (c) 2000 Michael Thomas <wart@kobold.org>
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
#ifndef _MORSE_H_INCLUDED

/*
Morse-encoded strings consist entirely of these characters.
A BLANK represents an error in the translation.
A single SPACE is used to separate letters.
A double SPACE is used to separate words.
*/

#define	DOT	'.'
#define	DASH	'-'
#define	SPACE	'x'
#define	BLANK	' '

char	*MorseStringToString(char *, char *);
char	*MorseStringToSpaceyString(char *, char *);
char	MorseStringToChar(char *);
int	MorseValid(char *);
char	*CharToMorse(char);
char	*StringToMorse(char *);

#define _MORSE_H_INCLUDED
#endif
