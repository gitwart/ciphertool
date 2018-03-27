/*
 * cipherDebug.h --
 * 	Include file for memory debugging.
 *
 * Copyright (C) 2003  Mike Thomas <wart@kobold.org>
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
 */

#ifndef _CIPHER_DEBUG_INCLUDED

#ifdef USE_DMALLOC

#ifdef ckalloc
#undef ckalloc
#define ckalloc malloc
#endif

#ifdef ckfree
#undef ckfree
#define ckfree free
#endif

#include <dmalloc.h>

#endif

#define _CIPHER_DEBUG_INCLUDED
#endif
