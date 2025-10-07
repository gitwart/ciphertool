/*
 * cipherIdentify.h --
 *
 *	This is the header file for cipher identification and feature extraction.
 *
 * Copyright (c) 2025
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

#ifndef _CIPHERIDENTIFY_H_INCLUDED
#define _CIPHERIDENTIFY_H_INCLUDED

#include <tcl.h>

#define MAX_PERIODIC_IOC_PERIODS 20

/*
 * Structure to hold extracted features from ciphertext
 * for use in cipher type identification
 */
typedef struct CipherFeatures {
    double ioc;                              /* Index of Coincidence */
    double periodicIoc[MAX_PERIODIC_IOC_PERIODS]; /* Periodic IoC for periods 2-20 */
    double chiSquared;                       /* Chi-squared statistic vs English */
    double entropy;                          /* Shannon entropy */
    double charFreq[26];                     /* Character frequencies a-z */
    double maxCharFreq;                      /* Maximum character frequency */
    double minCharFreq;                      /* Minimum character frequency (non-zero) */
    double meanCharFreq;                     /* Mean character frequency */
    double evenOddIocRatio;                  /* Ratio of IoC(even positions) / IoC(odd positions) */
    int length;                              /* Length of ciphertext */
    int distinctChars;                       /* Number of distinct characters */
    int hasSpaces;                           /* Whether text contains spaces */
    int hasPunctuation;                      /* Whether text contains punctuation */
} CipherFeatures;

/*
 * Function prototypes
 */
CipherFeatures* ExtractFeatures(const char *ciphertext);
void FreeCipherFeatures(CipherFeatures *features);
int CipherIdentifyCmd(ClientData clientData, Tcl_Interp *interp,
                      int argc, const char **argv);

#endif /* _CIPHERIDENTIFY_H_INCLUDED */
