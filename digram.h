/*
 * digram.h --
 * 	Include file for using the digram statistics routines.
 *
 * Copyright (C) 1995-2000  Mike Thomas <wart@kobold.org>
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

#ifndef _DIGRAM_INCLUDED

#define BAD_VALUE  0

int get_letter_value(char pt);
int get_letter_values(char *pt);
int get_digram_value(char pt1, char pt2, int language);
int get_digram_values(char *pt1, char *pt2, int language);
int get_digram_string_value(char *pt, int language);
int get_digram_string_average(char *pt, int language);
int find_best_fit(char *string1, char *string2, int language);
int freqfit(int *hist1, int *hist2, int length);
int freqval(int *hist1, int *hist2, int length, int offset);
int alphCharFit(char *string);
int alphHistFit(int *hist);
int histFit(int *hist1, int *hist2, int length);
int alphfit(int *hist);
int vw_alphfit(int *hist);
int ij_alphfit(int *hist);

#define _DIGRAM_INCLUDED

#endif
