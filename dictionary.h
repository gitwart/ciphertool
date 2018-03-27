/*
 * dictionary.h --
 *
 * 	Include file for the dictionary functions.
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

#ifndef _DICTIONARY_INCLUDED

#define DICTIONARY_LENGTH_CACHE		0x01
#define DICTIONARY_WORD_CACHE		0x02
#define DICTIONARY_PATTERN_CACHE	0x04
#define DICTIONARY_TRIGRAM_CACHE	0x08

typedef struct Dictionary {
    char *directory;
    int directoryChanged;
    int cacheTypes;
    /*
     * A table of words in the dictionary.  The keys of the table are
     * strings of the form "length", ie: "5".  The value
     * for each entry is a Tcl_Obj list  of Tcl_Obj words.
     */
    Tcl_HashTable *wordTable;
    /*
     * A table of words in the dictionary.  The keys of the table are
     * strings of the form "length,pattern", ie: "5,??ide".  The value
     * for each entry is a Tcl_Obj list  of Tcl_Obj words matching the
     * key pattern.
     */
    Tcl_HashTable *patternTable;
    /*
     * A table of trigrams.  The keys in the table are trigrams.  The values
     * are boolean 1 or 0, indicating if this trigram can appear in a
     * string of plaintext that contains only dictionary words.
     */
    Tcl_HashTable *trigramTable;
    /*
     * The lengths of words in the dictionary.
     */
    int *wordLengths;
} Dictionary;

Dictionary *createDictionary(void);
void deleteDictionary(Tcl_Interp *interp, Dictionary *dict);
void clearDictionary(Tcl_Interp *interp, Dictionary *dict, int cacheTypes);
int loadAvailableLengths(Tcl_Interp *interp, Dictionary *dict);

#define _DICTIONARY_INCLUDED
#endif
