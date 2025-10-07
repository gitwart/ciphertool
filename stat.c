/*
 * stat.c --
 *
 *	This file implements the Tcl "stat" command.  This command
 *	provides the ability to perform simple statistical analyses
 *	on aphanumeric ciphers.
 *
 * Copyright (c) 1995-2003 Michael Thomas <wart@kobold.org>
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
#include <cipher.h>
#include <string.h>
#include <digram.h>
#include <math.h>
#include <stat.h>

#include <cipherDebug.h>

#define MINKASISKIPERIOD 3
#define MAXKASISKIPERIOD 15
#define MAXKASISKILENGTH 8

static void _statHist(const char *, int *);
static char *_statKasiski(const char *, int, int, int);
/*
 * Usage:   stat histogram string
 *	    stat ioc string
 *	    stat kasiski period string
 *	    stat periodicioc string period
 *	    stat chisquared string
 *	    stat entropy string
 */

int
StatCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    const char	*cmd;
    const char 	*option;
    int		hist[256];
    char	temp[256];
    int		i,
    		count=0;
    double	ic=0.;
    int		minp=MINKASISKIPERIOD;
    int		maxp=MAXKASISKIPERIOD;
    int		maxlength=MAXKASISKILENGTH;
    char	*result=(char *)NULL;

    if (argc < 2) {
	Tcl_AppendResult(interp, "Usage:  ", *argv, " option string", (char *)NULL);
	return TCL_ERROR;
    }

    cmd = *argv;
    argv++, argc--;
    option = *argv;
    argv++, argc--;

    if (*option == 'i' && (strncmp(option, "ioc", 1) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", *argv, cmd, " string",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	/*
	 * Start off with a histogram
	 */

	_statHist(*argv, hist);

	for(i='a'; i <= 'z'; i++) {
	    ic += (double) hist[i] * ((double)hist[i] - 1);
	    count += hist[i];
	}
	ic /= (double) count * (count - 1);

	Tcl_PrintDouble(interp, ic, temp);

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;

    } else if (*option == 'h' && (strncmp(option, "histfit", 7) == 0)) {
	int bestFit = 0;
	int count1 = 0;
	int count2 = 0;
	int *hist1 = (int *)NULL;
	int *hist2 = (int *)NULL;
	Tcl_Obj *hist1Obj = (Tcl_Obj *)NULL;
	Tcl_Obj *hist2Obj = (Tcl_Obj *)NULL;
	Tcl_Obj **hist1ObjArr = (Tcl_Obj **)NULL;
	Tcl_Obj **hist2ObjArr = (Tcl_Obj **)NULL;

	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " hist1 hist2", (char *)NULL);
	    return TCL_ERROR;
	}
	hist1Obj = Tcl_NewStringObj(argv[0], strlen(argv[0]));
	hist2Obj = Tcl_NewStringObj(argv[1], strlen(argv[1]));

	if (Tcl_ListObjGetElements(interp, hist1Obj, &count1, &hist1ObjArr)) {
	    return TCL_ERROR;
	}
	if (Tcl_ListObjGetElements(interp, hist2Obj, &count2, &hist2ObjArr)) {
	    return TCL_ERROR;
	}

	if (count1 != count2) {
	    Tcl_SetResult(interp, "Number of elements in the histograms do not match.", TCL_STATIC);
	    return TCL_ERROR;
	}

	hist1 = (int *) ckalloc(sizeof(int) * count1);
	hist2 = (int *) ckalloc(sizeof(int) * count2);

	for (i=0; i < count1; i++) {
	    if (Tcl_GetIntFromObj(interp, hist1ObjArr[i], hist1+i) != TCL_OK) {
		ckfree((char *)hist1);
		ckfree((char *)hist2);
		return TCL_ERROR;
	    }
	    if (Tcl_GetIntFromObj(interp, hist2ObjArr[i], hist2+i) != TCL_OK) {
		ckfree((char *)hist1);
		ckfree((char *)hist2);
		return TCL_ERROR;
	    }
	}

	bestFit = freqfit(hist1, hist2, count1);
	sprintf(temp, "%d", bestFit);

	ckfree((char *)hist1);
	ckfree((char *)hist2);

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'h' && (strncmp(option, "histvals", 8) == 0)) {
	int fit = 0;
	int count1 = 0;
	int count2 = 0;
	int *hist1 = (int *)NULL;
	int *hist2 = (int *)NULL;
	Tcl_Obj *hist1Obj = (Tcl_Obj *)NULL;
	Tcl_Obj *hist2Obj = (Tcl_Obj *)NULL;
	Tcl_Obj **hist1ObjArr = (Tcl_Obj **)NULL;
	Tcl_Obj **hist2ObjArr = (Tcl_Obj **)NULL;

	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " hist1 hist2", (char *)NULL);
	    return TCL_ERROR;
	}
	hist1Obj = Tcl_NewStringObj(argv[0], strlen(argv[0]));
	hist2Obj = Tcl_NewStringObj(argv[1], strlen(argv[1]));

	if (Tcl_ListObjGetElements(interp, hist1Obj, &count1, &hist1ObjArr)) {
	    return TCL_ERROR;
	}
	if (Tcl_ListObjGetElements(interp, hist2Obj, &count2, &hist2ObjArr)) {
	    return TCL_ERROR;
	}

	if (count1 != count2) {
	    sprintf(temp, "%d vs. %d", count1, count2);
	    Tcl_AppendResult(interp, "Number of elements in the histograms do not match:  ", temp, (char *)NULL);
	    return TCL_ERROR;
	}

	hist1 = (int *) ckalloc(sizeof(int) * count1);
	hist2 = (int *) ckalloc(sizeof(int) * count2);

	for (i=0; i < count1; i++) {
	    if (Tcl_GetIntFromObj(interp, hist1ObjArr[i], hist1+i) != TCL_OK) {
		ckfree((char *)hist1);
		ckfree((char *)hist2);
		return TCL_ERROR;
	    }
	    if (Tcl_GetIntFromObj(interp, hist2ObjArr[i], hist2+i) != TCL_OK) {
		ckfree((char *)hist1);
		ckfree((char *)hist2);
		return TCL_ERROR;
	    }
	}

	for (i=0; i < count1; i++) {
	    fit = freqval(hist1, hist2, count1, i);
	    sprintf(temp, "%d", fit);
	    Tcl_AppendElement(interp, temp);
	}

	ckfree((char *)hist1);
	ckfree((char *)hist2);
	return TCL_OK;
    } else if (*option == 'h' && (strncmp(option, "histogram", 4) == 0)) {
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option, " string",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	_statHist(*argv, hist);

	for(i='a'; i <= 'z'; i++) {
	    sprintf(temp, "%c", i);
	    Tcl_AppendElement(interp, temp);
	    sprintf(temp, "%d", hist[i]);
	    Tcl_AppendElement(interp, temp);
	}

	return TCL_OK;
    } else if (*option == 'a' && (strncmp(option, "alphfit", 1) == 0)) {
	int fitVal=0;
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}

	fitVal = alphCharFit(argv[0]);

	sprintf(temp, "%d", fitVal);

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'k' && (strncmp(option, "kasiski", 1) == 0)) {
	if (argc != 1 && argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string ?minperiod maxperiod?", (char *)NULL);
	    return TCL_ERROR;
	}

	if (argc == 3) {
	    if ( (sscanf(argv[1], "%d", &minp) != 1) ||
		    (sscanf(argv[2], "%d", &maxp) != 1) ) {
		Tcl_SetResult(interp, "minperiod and maxperiod options must be integers", TCL_STATIC);
		return TCL_ERROR;
	    }

	    if (minp >= maxp) {
		Tcl_SetResult(interp, "minperiod must be smaller than max period", TCL_STATIC);
		return TCL_ERROR;
	    }

	    if (minp <= 0 || maxp <= 0) {
		Tcl_SetResult(interp, "minperiod and max period must be positive integers", TCL_STATIC);
		return TCL_ERROR;
	    }
	}

	result = _statKasiski(argv[0], minp, maxp, maxlength);

	Tcl_SetResult(interp, result, TCL_VOLATILE);
	ckfree(result);
	return TCL_OK;
    } else if (*option == 'p' && (strncmp(option, "periodicioc", 1) == 0)) {
	int period;
	double periodicIoc;

	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string period", (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[1], "%d", &period) != 1) {
	    Tcl_SetResult(interp, "period must be an integer", TCL_STATIC);
	    return TCL_ERROR;
	}

	periodicIoc = StatComputePeriodicIoC(argv[0], period);
	Tcl_PrintDouble(interp, periodicIoc, temp);
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'c' && (strncmp(option, "chisquared", 1) == 0)) {
	double chiSquared;

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}

	chiSquared = StatComputeChiSquared(argv[0]);
	Tcl_PrintDouble(interp, chiSquared, temp);
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'e' && (strncmp(option, "entropy", 1) == 0)) {
	double entropy;

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string", (char *)NULL);
	    return TCL_ERROR;
	}

	entropy = StatComputeEntropy(argv[0]);
	Tcl_PrintDouble(interp, entropy, temp);
	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else {
	Tcl_SetResult(interp, "Usage:  stat histogram|ioc|periodicioc|chisquared|entropy|alphfit|kasiski string", TCL_STATIC);
	return TCL_ERROR;
    }
}

static char *
_statKasiski(const char *ct, int minperiod, int maxperiod, int maxlength)
{
    int *ks;
    int length=0;
    char *string1=(char *)NULL;
    int i,
    	j,
	k,
	m;
    Tcl_DString result;
    char *buf;

    Tcl_DStringInit(&result);

    length = strlen(ct);
    buf = (char *)ckalloc(sizeof(char) * 32);

    ks = (int *)ckalloc(sizeof(int) * (maxperiod+1));
    for(i=0 ; i <= maxperiod; i++) {
	ks[i] = 0;
    }

    /*
     * Look for repeated sequences up to "maxlength" characters long
     */

    string1 = (char *)ckalloc(sizeof(char) * maxlength + 1);
    for(i=maxlength; i >= 1; i--) {
	/*
	 * Get a string of length i
	 */

	for(j = 0; j < length - i + 1; j++) {
	    strncpy(string1, ct+j, i);
	    string1[i] = '\0';

	    /*
	     * Search for a repeat of the string just obtained
	     */

	    for(k=j+i; k < length - i; k++) {
		if (strncmp(string1, ct+k, i) == 0) {
		    for(m=minperiod; m <= maxperiod; m++) {
			if ( (k - j)%m == 0) {
			    ks[m] += 1;
			}
		    }
		}
	    }
	}
    }

    for(i=minperiod; i <= maxperiod; i++) {
	Tcl_DStringStartSublist(&result);

	sprintf(buf, "%d", i);
	Tcl_DStringAppendElement(&result, buf);

	sprintf(buf, "%d", ks[i]);
	Tcl_DStringAppendElement(&result, buf);

	sprintf(buf, "%d", ks[i] * i);
	Tcl_DStringAppendElement(&result, buf);

	Tcl_DStringEndSublist(&result);
    }

    ckfree(buf);
    buf = (char *)ckalloc(sizeof(char) * Tcl_DStringLength(&result) + 1);
    strcpy(buf, Tcl_DStringValue(&result));

    if (ks) {
	ckfree((char *)ks);
    }

    return buf;
}

static void
_statHist(const char *string, int *hist)
{
    int		i;

    for(i=0; i < 256; i++) {
	hist[i] = 0;
    }

    while(*string) {
	hist[(int)*string++]++;
    }
}

/*
 * StatComputeIoC --
 *
 *	Computes the Index of Coincidence for the given text.
 *	IoC measures the probability that two randomly selected letters
 *	from the text are the same. For English text, IoC is typically
 *	around 0.065-0.067.
 *
 * Results:
 *	Returns the Index of Coincidence as a double.
 *
 * Side effects:
 *	None.
 */

double
StatComputeIoC(const char *text)
{
    int hist[256];
    int i;
    int count = 0;
    double ic = 0.0;

    _statHist(text, hist);

    for (i = 'a'; i <= 'z'; i++) {
        ic += (double) hist[i] * ((double)hist[i] - 1);
        count += hist[i];
    }

    if (count <= 1) {
        return 0.0;
    }

    ic /= (double) count * (count - 1);

    return ic;
}

/*
 * StatComputePeriodicIoC --
 *
 *	Computes the Index of Coincidence for every nth character
 *	in the text, where n is the period. This is useful for
 *	detecting polyalphabetic ciphers like Vigenere.
 *
 * Results:
 *	Returns the average IoC across all period positions.
 *
 * Side effects:
 *	None.
 */

double
StatComputePeriodicIoC(const char *text, int period)
{
    int length = strlen(text);
    int i, j;
    double totalIoc = 0.0;
    char *subtext = NULL;
    int subtextLen;

    if (period <= 0 || period > length) {
        return 0.0;
    }

    for (i = 0; i < period; i++) {
        /* Extract every period-th character starting at position i */
        subtextLen = (length - i + period - 1) / period;
        subtext = (char *)ckalloc(sizeof(char) * (subtextLen + 1));

        for (j = 0; j < subtextLen; j++) {
            if (i + j * period < length) {
                subtext[j] = text[i + j * period];
            }
        }
        subtext[subtextLen] = '\0';

        totalIoc += StatComputeIoC(subtext);
        ckfree(subtext);
    }

    return totalIoc / period;
}

/*
 * StatComputeChiSquared --
 *
 *	Computes the chi-squared statistic comparing the letter
 *	frequency distribution of the text to expected English
 *	letter frequencies. Lower values indicate better fit to English.
 *
 * Results:
 *	Returns the chi-squared statistic as a double.
 *
 * Side effects:
 *	None.
 */

double
StatComputeChiSquared(const char *text)
{
    int hist[256];
    int i;
    int count = 0;
    double chiSquared = 0.0;

    /* Expected frequencies for English text (from A-Z) */
    static const double expectedFreq[26] = {
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
        0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
        0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
        0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
        0.01974, 0.00074
    };

    _statHist(text, hist);

    /* Count total letters */
    for (i = 'a'; i <= 'z'; i++) {
        count += hist[i];
    }

    if (count == 0) {
        return 0.0;
    }

    /* Compute chi-squared statistic */
    for (i = 0; i < 26; i++) {
        double observed = hist['a' + i];
        double expected = expectedFreq[i] * count;

        if (expected > 0) {
            chiSquared += (observed - expected) * (observed - expected) / expected;
        }
    }

    return chiSquared;
}

/*
 * StatComputeEntropy --
 *
 *	Computes the Shannon entropy of the text based on letter
 *	frequencies. Higher entropy indicates more randomness.
 *	English text typically has entropy around 4.0-4.5 bits per character.
 *
 * Results:
 *	Returns the entropy in bits per character as a double.
 *
 * Side effects:
 *	None.
 */

double
StatComputeEntropy(const char *text)
{
    int hist[256];
    int i;
    int count = 0;
    double entropy = 0.0;
    double probability;

    _statHist(text, hist);

    /* Count total letters */
    for (i = 'a'; i <= 'z'; i++) {
        count += hist[i];
    }

    if (count == 0) {
        return 0.0;
    }

    /* Compute Shannon entropy */
    for (i = 'a'; i <= 'z'; i++) {
        if (hist[i] > 0) {
            probability = (double)hist[i] / count;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}
