/*
 * vigTypes.h --
 *
 *	This is the header file for the vigTypes.h file.
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

#ifndef _VIGTYPES_H_INCLUDED
#define _VIGTYPES_H_INCLUDED

#define VigenereGetKey(ct, pt) 	( (ct-pt+26)%26 + 'a')
#define VigenereGetCt(key, pt) 	( (key+pt-'a'-'a')%26 + 'a')
#define VigenereGetPt(key, ct) 	( (ct-key+26)%26 + 'a')

#define VariantGetKey(ct, pt) 	( (pt-ct+26)%26 + 'a')
#define VariantGetCt(key, pt) 	( (pt-key+26)%26 + 'a')
#define VariantGetPt(key, ct) 	( (key+ct-'a'-'a')%26 + 'a')

#define BeaufortGetKey(ct, pt) 	( (pt+ct-'a'-'a')%26 + 'a')
#define BeaufortGetCt(key, pt) 	( (key-pt+26)%26 + 'a')
#define BeaufortGetPt(key, ct) 	( (key-ct+26)%26 + 'a')

char PortaGetKey _ANSI_ARGS_((char ct, char pt));
char PortaGetPt _ANSI_ARGS_((char key, char ct));
char PortaGetCt _ANSI_ARGS_((char key, char pt));

int PortaxGetPt	 _ANSI_ARGS_((char key, char ct1, char ct2,
	    	char *pt1, char *pt2));

#endif /* _VIGTYPES_H_INCLUDED */
