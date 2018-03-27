/*
 * vigTypes.c --
 *
 *	This file implements the pt/ct/key conversions for vigenere
 *	type ciphers:  vigenere, variant, beaufort, porta, and gronsfeld.
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

#include <tcl.h>
#include <string.h>
#include <cipher.h>

#include <cipherDebug.h>

static char _portaCtPt[26][26] = {
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000acegikmoqsuwy" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000yacegikmoqsuw" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000wyacegikmoqsu" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000uwyacegikmoqs" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000suwyacegikmoq" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000qsuwyacegikmo" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000oqsuwyacegikm" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000moqsuwyacegik" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000kmoqsuwyacegi" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000ikmoqsuwyaceg" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000gikmoqsuwyace" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000egikmoqsuwyac" },
    { "\000\000\000\000\000\000\000\000\000\000\000\000\000cegikmoqsuwya" },
    { "aywusqomkigec\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "caywusqomkige\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "ecaywusqomkig\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "gecaywusqomki\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "igecaywusqomk\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "kigecaywusqom\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "mkigecaywusqo\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "omkigecaywusq\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "qomkigecaywus\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "sqomkigecaywu\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "usqomkigecayw\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "wusqomkigecay\000\000\000\000\000\000\000\000\000\000\000\000\000" },
    { "ywusqomkigeca\000\000\000\000\000\000\000\000\000\000\000\000\000" }};

static char _portaCtKey[26][26] = {
    { "nnooppqqrrssttuuvvwwxxyyzz" },
    { "ooppqqrrssttuuvvwwxxyyzznn" },
    { "ppqqrrssttuuvvwwxxyyzznnoo" },
    { "qqrrssttuuvvwwxxyyzznnoopp" },
    { "rrssttuuvvwwxxyyzznnooppqq" },
    { "ssttuuvvwwxxyyzznnooppqqrr" },
    { "ttuuvvwwxxyyzznnooppqqrrss" },
    { "uuvvwwxxyyzznnooppqqrrsstt" },
    { "vvwwxxyyzznnooppqqrrssttuu" },
    { "wwxxyyzznnooppqqrrssttuuvv" },
    { "xxyyzznnooppqqrrssttuuvvww" },
    { "yyzznnooppqqrrssttuuvvwwxx" },
    { "zznnooppqqrrssttuuvvwwxxyy" },
    { "aammllkkjjiihhggffeeddccbb" },
    { "bbaammllkkjjiihhggffeeddcc" },
    { "ccbbaammllkkjjiihhggffeedd" },
    { "ddccbbaammllkkjjiihhggffee" },
    { "eeddccbbaammllkkjjiihhggff" },
    { "ffeeddccbbaammllkkjjiihhgg" },
    { "ggffeeddccbbaammllkkjjiihh" },
    { "hhggffeeddccbbaammllkkjjii" },
    { "iihhggffeeddccbbaammllkkjj" },
    { "jjiihhggffeeddccbbaammllkk" },
    { "kkjjiihhggffeeddccbbaammll" },
    { "llkkjjiihhggffeeddccbbaamm" },
    { "mmllkkjjiihhggffeeddccbbaa" }};

char
PortaGetKey(char ct, char pt)
{
    if (ct >= 'a' && ct < 'z' && pt >= 'a' && pt <= 'z') {
	return _portaCtPt[ct-'a'][pt-'a'];
    } else {
	return (char)NULL;
    }
}

char
PortaGetCt(char key, char pt)
{
    if (key >= 'a' && key < 'z' && pt >= 'a' && pt <= 'z') {
	return _portaCtKey[pt-'a'][key-'a'];
    } else {
	return (char)NULL;
    }
}

char
PortaGetPt(char key, char ct)
{
    if (key >= 'a' && key < 'z' && ct >= 'a' && ct <= 'z') {
	return _portaCtKey[ct-'a'][key-'a'];
    } else {
	return (char)NULL;
    }
}

int
PortaxGetPt(char key, char ct1, char ct2, char *pt1, char *pt2)
{
    int	pt1row;
    int	pt2row;
    int	ct1row;
    int	ct2row;
    int	pt1col;
    int	pt2col;
    int	ct1col;
    int	ct2col;
    int keycol;

    if (key < 'a' || key > 'z') {
	*pt1 = (char)NULL;
	*pt2 = (char)NULL;
	return 0;
    }

    if (ct1 < 'a' || ct1 > 'z' || ct2 < 'a' || ct2 > 'z') {
	*pt1 = (char)NULL;
	*pt2 = (char)NULL;
	return 0;
    }

    keycol = (key - 'a') / 2;

    if (ct1 <= 'm') {
	ct1col = ct1 - 'a' + keycol;
    } else {
	ct1col = ct1 - 'n';
	if (ct1col < keycol) {
	    ct1col = ct1col + 13;
	}
    }
    ct1row = (ct1-'a')/13;
    ct2row = ((ct2-'a')%2) + 2;
    ct2col = (ct2 - 'a')/2;
    if (ct2col < keycol) {
	ct2col = ct2col + 13;
    }

    pt1col = ct2col;
    pt2col = ct1col;

    if (ct1col == ct2col) {
	pt1row = 1 - ct1row;
	pt2row = 3 - ct2row + 2;
    } else {
	pt1row = ct1row;
	pt2row = ct2row;
    }

    if (pt1row == 0) {
	*pt1 = pt1col - keycol + 'a';
    } else {
	*pt1 = pt1col%13 + 'n';
    }

    *pt2 = ((pt2row - 2) + pt2col * 2) % 26 + 'a';

    return 1;
}
