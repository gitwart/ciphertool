/*
 * digram.c --
 *
 *	This file implements routines for performing digram frequency
 *	counts on textual input.
 *
 * Copyright (c) 1995-2000 Michael Thomas <wart@kobold.org>
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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include <score.h>
#include <digram.h>

#include <cipherDebug.h>

static int letter_freq[] = { 1863, 954, 1477, 1644, 2114, 1447, 1204, 1544,
   1869, 301, 477, 1544, 1398, 1892, 1869, 1431, 477, 1887, 1799, 1969, 1431, 
   1114, 1204, 699, 1279, 0};

static int ij_letter_freq[] = { 1863, 954, 1477, 1644, 2114, 1447, 1204, 1544,
   2170, 477, 1544, 1398, 1892, 1869, 1431, 477, 1887, 1799, 1969, 1431, 
   1114, 1204, 699, 1279, 0};

static int vw_letter_freq[] = { 1863, 954, 1477, 1644, 2114, 1447, 1204, 1544,
   1869, 301, 477, 1544, 1398, 1892, 1869, 1431, 477, 1887, 1799, 1969, 1431, 
   2318, 699, 1279, 0};

extern ScoreItem *defaultScoreItem;
extern ScoreItem *initialScoreItem;

int
get_letter_value(char pt)
{
    if (isalpha(pt)) {
	/*
	printf("%d\n", (int)((pt|' ')-'a'));
	*/
	return letter_freq[(pt|' ')-'a'];
    }
    else {
	return 0;
    }
}

int
get_letter_values(char *pt)
{
    int value=0;

    while(*pt){
	if(isalpha(*pt)) {
	    value += letter_freq[((*pt)|' ') - 'a'];
	}
	pt++;
    }
    return value;
}

int
get_digram_value(char pt1, char pt2, int language)
{
    char temp_str[3];
    if (initialScoreItem == NULL) {
	return 0;
    }
    temp_str[0] = pt1;
    temp_str[1] = pt2;
    temp_str[2] = '\0';
    return (int) ((initialScoreItem->typePtr->elemValueProc)(NULL, initialScoreItem, (const char *) temp_str) * 100.0);
}

int
get_digram_values(char *pt1, char *pt2, int language)
{
    int i;
    double value = 0.0;
    char temp_str[3];
    temp_str[2] = '\0';

    if (initialScoreItem == NULL) {
	return 0;
    }

    for(i = 0; pt1[i] && pt2[i];  i++) {
	temp_str[0] = pt1[i];
	temp_str[1] = pt2[i];
	value += (initialScoreItem->typePtr->elemValueProc)(NULL, initialScoreItem, (const char *) temp_str);
    }

    return (int) (value * 100.0);
}

int get_digram_string_average(char *pt, int language)
{
    int i, value=0;
    int count = 0;
    int length = strlen(pt);

    for(i=1; i < length; i++) {
	value += get_digram_value(pt[i-1], pt[i], language);

	if (isalpha(pt[i]) && isalpha(pt[i-1])) {
	    count++;
	}
    }

    if (count) {
	return (int)(value / count);
    } else {
	return 0;
    }
}


int
find_best_fit(char *string1, char *string2, int language)
{
    int bestrot = 0, maxval = 0, value = 0;
    int len1, len2;
    int i, j;

    len1 = strlen(string1);
    len2 = strlen(string2);

    for(i = 0; i < len1 && len1 == len2; i++) {
	for(j = 0, value = 0; j < len1; j++) {
	    value += get_digram_value(string1[j], string2[(i+j)%len2], language);
	}
	/*
	printf("   %d: ", value);
	for(j=0; j < 25; j++) {
	    printf("%c ", string1[j]);
	}
	printf("\n");
	printf("%2d,%d: ", i, value);
	for(j=0; j < 25; j++) {
	    printf("%c ", string2[(i+j)%len2]);
	}
	printf("\n\n");
	*/
	if(value > maxval) {
	    maxval = value;
	    bestrot = i;
	}
    }

    return len2-bestrot;
}

int
alphfit(int *hist)
{
    return freqfit(hist, letter_freq, 26);
}

/*
 * Fit the input histogram to a normal alphabet with i and j paired together
 */

int
ij_alphfit(int *hist)
{
    return freqfit(hist, ij_letter_freq, 25);
}

/*
 * Fit the input histogram to a normal alphabet with v and w paired together
 */

int
vw_alphfit(int *hist)
{
    return freqfit(hist, vw_letter_freq, 25);
}

/*
 * Slide one histogram along the other until the best "fit" is found
 * for the two
 */

int
freqfit(int *hist1, int *hist2, int length)
{
    double	maxvalue=0.0;
    int		maxstart=0;
    int		start,
		i,
		n;
    double	value;

    /*
     * Loop through every possible alignment of the two histograms.
     * 'start' refers to the position in the second histogram where
     * the beginning of the first histogram is being matched to.
     */

    for(start=0; start < length; start++) {
	/*
	 * Find the match value for this histogram
	 */

	for(i=0, value=0.0; i < length; i++) {
	    n = hist2[(i+start)%length];

	    value += n * hist1[i];
	}

	if (value > maxvalue) {
	    maxvalue = value;
	    maxstart = start;
	}
    }

    return maxstart;
}

/*
 * Return the goodness value of the match of the two histograms.
 */

int
freqval(int *hist1, int *hist2, int length, int offset)
{
    int		i;
    double	value;

    for(i=0, value=0.0; i < length; i++) {
	value += hist2[(i+offset)%length] * hist1[i];
    }

    return value;
}

int
alphCharFit(const char *string)
{
    int hist[26];
    int i;

    for(i=0; i < 26; i++) {
	hist[i] = 0;
    }

    for(i=0; string[i]; i++) {
	if (string[i] >= 'a' && string[i] <= 'z') {
	    hist[string[i] - 'a']++;
	}
    }

    return histFit(hist, letter_freq, 26);
}

int
alphHistFit(int *hist)
{
    return histFit(hist, letter_freq, 26);
}

/*
 * Return the value for the fit of two histograms
 */

int
histFit(int *hist1, int *hist2, int length)
{
    int i;
    int value=0;

    for(i=0, value=0; i < length; i++) {
	value += hist2[i] * hist1[i];
    }

    return value;
}
