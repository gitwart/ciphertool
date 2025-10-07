/*
 * cipherIdentify.c --
 *
 *	This file implements feature extraction and identification
 *	support for automatically determining cipher types.
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

#include <tcl.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <cipherIdentify.h>
#include <stat.h>

/*
 * ExtractFeatures --
 *
 *	Extracts statistical features from ciphertext that can be used
 *	to identify the cipher type. This includes IoC, periodic IoC,
 *	chi-squared, entropy, character frequencies, and other indicators.
 *
 * Results:
 *	Returns a pointer to a CipherFeatures structure containing all
 *	computed features. The caller must free this with FreeCipherFeatures().
 *
 * Side effects:
 *	Allocates memory for the CipherFeatures structure.
 */

CipherFeatures*
ExtractFeatures(const char *ciphertext)
{
    CipherFeatures *features;
    int length = strlen(ciphertext);
    int i;
    int charCount[256] = {0};
    int totalChars = 0;
    int distinctChars = 0;
    double sumFreq = 0.0;
    const char *p;
    char *evenChars = NULL;
    char *oddChars = NULL;
    int evenLen = 0;
    int oddLen = 0;

    /* Allocate the features structure */
    features = (CipherFeatures *)ckalloc(sizeof(CipherFeatures));
    memset(features, 0, sizeof(CipherFeatures));

    features->length = length;

    if (length == 0) {
        return features;
    }

    /* Compute basic statistics */
    features->ioc = StatComputeIoC(ciphertext);
    features->chiSquared = StatComputeChiSquared(ciphertext);
    features->entropy = StatComputeEntropy(ciphertext);

    /* Compute periodic IoC for periods 2-20 */
    for (i = 0; i < MAX_PERIODIC_IOC_PERIODS; i++) {
        features->periodicIoc[i] = StatComputePeriodicIoC(ciphertext, i + 2);
    }

    /* Count character frequencies */
    for (p = ciphertext; *p; p++) {
        charCount[(unsigned char)*p]++;
        if (isspace((unsigned char)*p)) {
            features->hasSpaces = 1;
        }
        if (ispunct((unsigned char)*p)) {
            features->hasPunctuation = 1;
        }
    }

    /* Calculate character frequency statistics */
    features->minCharFreq = 1.0;
    for (i = 'a'; i <= 'z'; i++) {
        if (charCount[i] > 0) {
            totalChars += charCount[i];
            distinctChars++;
        }
    }

    features->distinctChars = distinctChars;

    if (totalChars > 0) {
        for (i = 0; i < 26; i++) {
            features->charFreq[i] = (double)charCount['a' + i] / totalChars;

            if (features->charFreq[i] > features->maxCharFreq) {
                features->maxCharFreq = features->charFreq[i];
            }

            if (features->charFreq[i] > 0 && features->charFreq[i] < features->minCharFreq) {
                features->minCharFreq = features->charFreq[i];
            }

            sumFreq += features->charFreq[i];
        }

        if (distinctChars > 0) {
            features->meanCharFreq = sumFreq / distinctChars;
        }
    } else {
        features->minCharFreq = 0.0;
    }

    /* Compute even/odd position IoC ratio */
    evenLen = (length + 1) / 2;
    oddLen = length / 2;

    if (evenLen > 0) {
        evenChars = (char *)ckalloc(sizeof(char) * (evenLen + 1));
        for (i = 0; i < evenLen && i * 2 < length; i++) {
            evenChars[i] = ciphertext[i * 2];
        }
        evenChars[evenLen] = '\0';
    }

    if (oddLen > 0) {
        oddChars = (char *)ckalloc(sizeof(char) * (oddLen + 1));
        for (i = 0; i < oddLen && i * 2 + 1 < length; i++) {
            oddChars[i] = ciphertext[i * 2 + 1];
        }
        oddChars[oddLen] = '\0';
    }

    if (evenChars && oddChars && oddLen > 1) {
        double evenIoc = StatComputeIoC(evenChars);
        double oddIoc = StatComputeIoC(oddChars);

        if (oddIoc > 0.0 && !isnan(evenIoc) && !isnan(oddIoc)) {
            features->evenOddIocRatio = evenIoc / oddIoc;
        } else {
            features->evenOddIocRatio = 1.0;
        }
    } else {
        features->evenOddIocRatio = 1.0;
    }

    if (evenChars) {
        ckfree(evenChars);
    }
    if (oddChars) {
        ckfree(oddChars);
    }

    return features;
}

/*
 * FreeCipherFeatures --
 *
 *	Frees a CipherFeatures structure allocated by ExtractFeatures().
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Frees the memory associated with the features structure.
 */

void
FreeCipherFeatures(CipherFeatures *features)
{
    if (features) {
        ckfree((char *)features);
    }
}

/*
 * CipherIdentifyCmd --
 *
 *	Tcl command for cipher identification. Uses subcommands to
 *	provide different functionality.
 *
 *	Usage: identify features ciphertext
 *	       identify type ciphertext ?options?
 *
 * Results:
 *	Returns TCL_OK on success, TCL_ERROR on failure.
 *
 * Side effects:
 *	Depends on subcommand.
 */

int
CipherIdentifyCmd(ClientData clientData, Tcl_Interp *interp,
                  int argc, const char **argv)
{
    CipherFeatures *features;
    char temp[256];
    int i;
    Tcl_DString result;
    const char *subcommand;

    if (argc < 2) {
        Tcl_AppendResult(interp, "Usage: ", argv[0], " features ciphertext",
                        (char *)NULL);
        return TCL_ERROR;
    }

    subcommand = argv[1];

    if (strcmp(subcommand, "features") == 0) {
        /* Extract and return features as a dictionary */
        if (argc != 3) {
            Tcl_AppendResult(interp, "Usage: ", argv[0], " features ciphertext",
                            (char *)NULL);
            return TCL_ERROR;
        }

        features = ExtractFeatures(argv[2]);

    Tcl_DStringInit(&result);

    /* Build a Tcl dictionary with all features */
    Tcl_DStringAppendElement(&result, "ioc");
    Tcl_PrintDouble(interp, features->ioc, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "chisquared");
    Tcl_PrintDouble(interp, features->chiSquared, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "entropy");
    Tcl_PrintDouble(interp, features->entropy, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "length");
    sprintf(temp, "%d", features->length);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "distinctChars");
    sprintf(temp, "%d", features->distinctChars);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "maxCharFreq");
    Tcl_PrintDouble(interp, features->maxCharFreq, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "minCharFreq");
    Tcl_PrintDouble(interp, features->minCharFreq, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "meanCharFreq");
    Tcl_PrintDouble(interp, features->meanCharFreq, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "evenOddIocRatio");
    Tcl_PrintDouble(interp, features->evenOddIocRatio, temp);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "hasSpaces");
    sprintf(temp, "%d", features->hasSpaces);
    Tcl_DStringAppendElement(&result, temp);

    Tcl_DStringAppendElement(&result, "hasPunctuation");
    sprintf(temp, "%d", features->hasPunctuation);
    Tcl_DStringAppendElement(&result, temp);

    /* Add periodic IoC values */
    Tcl_DStringAppendElement(&result, "periodicIoc");
    Tcl_DStringStartSublist(&result);
    for (i = 0; i < MAX_PERIODIC_IOC_PERIODS; i++) {
        Tcl_PrintDouble(interp, features->periodicIoc[i], temp);
        Tcl_DStringAppendElement(&result, temp);
    }
    Tcl_DStringEndSublist(&result);

    /* Add character frequencies */
    Tcl_DStringAppendElement(&result, "charFreq");
    Tcl_DStringStartSublist(&result);
    for (i = 0; i < 26; i++) {
        Tcl_PrintDouble(interp, features->charFreq[i], temp);
        Tcl_DStringAppendElement(&result, temp);
    }
    Tcl_DStringEndSublist(&result);

        Tcl_SetResult(interp, Tcl_DStringValue(&result), TCL_VOLATILE);
        Tcl_DStringFree(&result);

        FreeCipherFeatures(features);

        return TCL_OK;
    } else if (strcmp(subcommand, "type") == 0) {
        /* Identify cipher type - delegates to Tcl library */
        int result;
        char *script;
        int scriptLen;

        if (argc < 3) {
            Tcl_AppendResult(interp, "Usage: ", argv[0], " type ciphertext ?options?",
                            (char *)NULL);
            return TCL_ERROR;
        }

        /* Build Tcl command to call CipherIdentify::identifyCipher */
        scriptLen = strlen("CipherIdentify::identifyCipher") + strlen(argv[2]) + 100;
        for (i = 3; i < argc; i++) {
            scriptLen += strlen(argv[i]) + 10;
        }

        script = (char *)ckalloc(scriptLen);
        strcpy(script, "package require CipherIdentify; CipherIdentify::identifyCipher {");
        strcat(script, argv[2]);
        strcat(script, "}");

        for (i = 3; i < argc; i++) {
            strcat(script, " ");
            strcat(script, argv[i]);
        }

        result = Tcl_Eval(interp, script);
        ckfree(script);

        return result;
    } else {
        Tcl_AppendResult(interp, "Unknown subcommand \"", subcommand,
                        "\": should be features or type", (char *)NULL);
        return TCL_ERROR;
    }
}
