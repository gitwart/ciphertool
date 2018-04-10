/*
 * keygen.c --
 *
 *	This file implements the "key" Tcl command for generating cipher
 *	keys.
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

#include <string.h>
#include <tcl.h>
#include <stdlib.h>
#include <keygen.h>
#include <vigTypes.h>
#include <cipher.h>

#include <cipherDebug.h>

/*
 * Usage:   key generate -k1 string
 *	    key generate -k2 string
 *	    key generate -k1list string
 *	    key generate -k2list string
 *	    key generate -k3 string
 *	    key generate -k3list string
 *	    key generate -k4 string1 string2
 *	    key generate -k4list string1 string2
 *          key match  key1 key2
 *          key convert ?type? char1 char2
 *          key ordervalue  key
 *          key numtostring number
 *          key caesarshift string number
 */

int
KeygenCmd(ClientData clientData, Tcl_Interp *interp, int argc, const char **argv)
{
    const char	*cmd;
    const char 	*option;
    char	temp[256];
    int		i;
    Tcl_Obj	*resultPtr;

    if (argc < 2) {
	Tcl_AppendResult(interp, "Usage:  ", *argv,
		" option ?args?", (char *)NULL);
	return TCL_ERROR;
    }

    cmd = *argv;
    argv++, argc--;
    option = *argv;
    argv++, argc--;

    if (*option == 'g' && (strncmp(option, "generate", 1) == 0)) {
	const char *type;

	if (argc < 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ",
		    option, " option ?args?", (char *)NULL);
	    return TCL_ERROR;
	}

	type = *argv;
	argv++, argc--;

	if (*type == '-' && (strncmp(type, "-k1list", 7) == 0)) {
	    char fixedKey[26];
	    int j;

	    if (argc != 1) {
		Tcl_AppendResult(interp, "Usage:  ", cmd, " ",
			option, " ", type, " string", (char *)NULL);
		return TCL_ERROR;
	    }

	    if (KeyGenerateK1(interp, *argv, fixedKey) != TCL_OK) {
		return TCL_ERROR;
	    }

	    for(i=0; i < 26; i++) {
		for(j=0; j < 26; j++) {
		    temp[(i+j)%26] = fixedKey[j];
		}
		temp[26] = '\0';

		Tcl_AppendElement(interp, temp);
	    }

	    return TCL_OK;
	} else if (*type == '-' && (strncmp(type, "-k1", 3) == 0)) {
	    if (argc != 1) {
		Tcl_AppendResult(interp, "Usage:  ", cmd, " ",
			option, " ", type, " string", (char *)NULL);
		return TCL_ERROR;
	    }

	    if (KeyGenerateK1(interp, *argv, temp) != TCL_OK) {
		return TCL_ERROR;
	    }

	    Tcl_SetResult(interp, temp, TCL_VOLATILE);
	    return TCL_OK;
	} else if (*type == '-' && (strncmp(type, "-k2list", 7) == 0)) {
	    Tcl_SetResult(interp, "This function is not yet written",
		    TCL_STATIC);
	    return TCL_ERROR;
	} else if (*type == '-' && (strncmp(type, "-k2", 3) == 0)) {
	    Tcl_SetResult(interp, "This function is not yet written",
		    TCL_STATIC);
	    return TCL_ERROR;
	} else if (*type == '-' && (strncmp(type, "-k3list", 7) == 0)) {
	    char fixedKey[26];
	    int j;

	    Tcl_SetResult(interp, "This function is not yet written",
		    TCL_STATIC);
	    return TCL_ERROR;

	    if (argc != 1) {
		Tcl_AppendResult(interp, "Usage:  ", cmd, " ",
			option, " ", type, " string", (char *)NULL);
		return TCL_ERROR;
	    }


	    if (KeyGenerateK1(interp, *argv, fixedKey) != TCL_OK) {
		return TCL_ERROR;
	    }

	    for(i=0; i < 26; i++) {
		for(j=0; j < 26; j++) {
		    temp[(i+j)%26] = fixedKey[j];
		}
		temp[26] = '\0';

		Tcl_AppendElement(interp, temp);
	    }
	    return TCL_OK;
	} else if (*type == '-' && (strncmp(type, "-k3", 3) == 0)) {
	    Tcl_SetResult(interp, "This function is not yet written",
		    TCL_STATIC);
	    return TCL_ERROR;
	} else if (*type == '-' && (strncmp(type, "-k4list", 7) == 0)) {
	    Tcl_SetResult(interp, "This function is not yet written",
		    TCL_STATIC);
	    return TCL_ERROR;
	} else if (*type == '-' && (strncmp(type, "-k4", 3) == 0)) {
	    Tcl_SetResult(interp, "This function is not yet written",
		    TCL_STATIC);
	    return TCL_ERROR;
	} else {
	    Tcl_AppendResult(interp, "Unknown option ", type,
		    ".  Must be one of '-k1', '-k1list', '-k2', '-k2list', '-k3', '-k3list', '-k4', '-k4list'",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'c' && (strncmp(option, "convert", 2) == 0)) {
	const char *subcommand;
	temp[1] = '\0';

	if (argc != 3) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " type char1 char2", (char *)NULL);
	    return TCL_ERROR;
	}

	subcommand = argv[0];
	if (strncmp(subcommand, "vigpt", 5) == 0) {
	    temp[0] = VigenereGetPt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "vigct", 5) == 0) {
	    temp[0] = VigenereGetCt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "vigkey", 6) == 0) {
	    temp[0] = VigenereGetKey(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "varpt", 5) == 0) {
	    temp[0] = VariantGetPt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "varct", 5) == 0) {
	    temp[0] = VariantGetCt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "varkey", 6) == 0) {
	    temp[0] = VariantGetKey(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "beapt", 5) == 0) {
	    temp[0] = BeaufortGetPt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "beact", 5) == 0) {
	    temp[0] = BeaufortGetCt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "beakey", 6) == 0) {
	    temp[0] = BeaufortGetKey(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "prtpt", 5) == 0) {
	    temp[0] = PortaGetPt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "prtct", 5) == 0) {
	    temp[0] = PortaGetCt(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "prtkey", 6) == 0) {
	    temp[0] = PortaGetKey(argv[1][0], argv[2][0]);
	} else if (strncmp(subcommand, "portaxpt", 6) == 0
		|| strncmp(subcommand, "portaxct", 6) == 0) {
	    PortaxGetPt(argv[1][0], argv[2][0], argv[2][1],
		    temp, temp+1);
	    temp[2] = '\0';
	} else {
	    Tcl_AppendResult(interp, "Unknown type ", subcommand,
		    "Must be one of vigpt, vigct, vigkey, varpt, varct, varkey, beapt, beact, beakey, prtct, prtpt, prtkey, portaxpt, portaxct",
		    (char *)NULL);
	    return TCL_ERROR;
	}

	Tcl_SetResult(interp, temp, TCL_VOLATILE);
	return TCL_OK;
    } else if (*option == 'n' && (strncmp(option, "numtostring", 1) == 0)) {
	long number;
	char *numString;
	
	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " ", option, " number", (char *)NULL);
	    return TCL_ERROR;
	}

	if (sscanf(argv[0], "%ld", &number) != 1) {
	    Tcl_SetResult(interp, "Argument must be a number", TCL_STATIC);
	    return TCL_ERROR;
	}

	numString = KeyGenerateNum(interp, number);

	if (!numString) {
	    return TCL_ERROR;
	}

	Tcl_SetResult(interp, numString, TCL_VOLATILE);

	ckfree(numString);

	return TCL_OK;
    } else if (*option == 'o' && (strncmp(option, "ordervalue", 1) == 0)) {
	int value=0;
	const char *key;
	resultPtr = Tcl_GetObjResult(interp);

	if (argc != 1) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " ", option, " key", (char *)NULL);
	    return TCL_ERROR;
	}

	key = argv[0];

	if (strlen(key) > 0) {
	    for (i=1; key[i]; i++) {
                if (key[i] - key[i-1] == 1) {
                    value += 3;
                } else if (key[i] - key[i-1] == 2) {
                    value += 2;
                } else if (key[i] - key[i-1] == 3) {
                    value += 1;
                }

                /*
		if (key[i] > key[i-1] && (key[i] - key[i-1]) < 4) {
		    value++;
		}
                */
	    }
	}

	Tcl_SetIntObj(resultPtr, value);
	return TCL_OK;
    } else if (*option == 'm' && (strncmp(option, "match", 1) == 0)) {
	const char *key1;
	const char *key2;
	int	match=1;
	resultPtr = Tcl_GetObjResult(interp);

	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd,
		    " ", option, " key1 key2", (char *)NULL);
	    return TCL_ERROR;
	}

	key1 = argv[0];
	key2 = argv[1];

	/*
	 * Two keys match if the strings are the same.  Spaces in either
	 * key count as wildcards.
	 */


	match=1;
	for(i=0; key1[i] && key2[i]; i++) {
	    if (! (key1[i] == ' ' ||
		    key2[i] == ' ' ||
		    key1[i] == key2[i]) ) {
		match = 0;
	    }
	}

	/*
	 * Test if the keys were the same length
	 */

	if (key1[i] || key2[i]) {
	    match = 0;
	}

	Tcl_SetBooleanObj(resultPtr, match);
	return TCL_OK;
    } else if (*option == 'c' && (strncmp(option, "caesarshift", 2) == 0)) {
        int shift = 0;
        char *shiftedString = (char *)NULL;

	if (argc != 2) {
	    Tcl_AppendResult(interp, "Usage:  ", cmd, " ", option,
		    " string amount", (char *)NULL);
	    return TCL_ERROR;
	}

	resultPtr = Tcl_GetObjResult(interp);

        if (sscanf(argv[1], "%d", &shift) != 1) {
            Tcl_SetStringObj(resultPtr, "caesar shift amount must be a number", -1);
            return TCL_ERROR;
        }

        shiftedString = strdup(argv[0]);

        CaesarShift(shiftedString, shift);

        Tcl_SetStringObj(resultPtr, shiftedString, -1);
        return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Unknown option ", option, (char *)NULL);
	Tcl_AppendResult(interp, "\nMust be one of:  ", cmd,
			" generate string", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" match key1 key2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" ordervalue string", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" numtostring int", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" convert type char1 char2", (char *)NULL);
	Tcl_AppendResult(interp, "\n                 ", cmd,
			" caesarshift string amount", (char *)NULL);
	return TCL_ERROR;
    }
}

int
KeyGenerateK1(Tcl_Interp *interp, const char *keyword, char *result)
{
    char usedLetters[26];
    int	resultIndex;
    int i;

    for(i=0; i < 26; i++) {
	usedLetters[i] = 0;
	result[i]='\0';
    }

    resultIndex=0;
    for(i=0; keyword[i]; i++) {
	char c = keyword[i];

	if (c < 'a' || c > 'z') {
	    Tcl_AppendResult(interp, "Invalid character found in keyword ", keyword, ".  All letters must be lowercase from a-z", (char *)NULL);
	    return TCL_ERROR;
	}

	if (usedLetters[c -'a'] == 0) {
	    result[resultIndex] = c;
	    resultIndex++;
	    usedLetters[c - 'a'] = 1;
	}
    }

    for(i=0; i < 26; i++) {
	if (usedLetters[i] == 0) {
	    result[resultIndex] = i + 'a';
	    resultIndex++;
	}
    }
    if (resultIndex != 26) {
	fprintf(stderr, "Fatal indexing error! %s: line %d\n",
		__FILE__, __LINE__);
	abort();
    }
    result[26]='\0';

    return TCL_OK;
}

char *
KeyGenerateNum(Tcl_Interp *interp, long value)
{
    char *numString;
    char *result;
    char *unitString;
    int  curIndex=0;
    long dividend;

    if (value > 999999999) {
	Tcl_SetResult(interp, "Value too large.  Must be less than one billion",
		TCL_STATIC);
	return (char *)NULL;
    }

    result = (char *)ckalloc(sizeof(char) * MAX_NUM_STRING_LENGTH);
    result[0] = '\0';

    if (value == 0) {
	strcpy(result, "zero");
    } else {
	while (value) {
	    if (value > 999999) {
		dividend = 1000000;
		unitString = " million";
	    } else if (value > 999) {
		dividend = 1000;
		unitString = " thousand";
	    } else {
		dividend = 1;
		unitString = "";
	    }

	    if (value / dividend) {
		numString = KeyTripletToString((int) (value / dividend));
		if (curIndex != 0) {
		    result[curIndex] = ' ';
		    curIndex++;
		}
		strcpy(result+curIndex, numString);
		curIndex = curIndex + strlen(numString);
		strcpy(result+curIndex, unitString);
		curIndex = curIndex + strlen(unitString);

		ckfree(numString);
	    }
	    value = value - ((int)(value / dividend)) * dividend;
	}
	result[curIndex] = '\0';
    }

    return result;
}

char *
KeyTripletToString(int value)
{
    int hundreds;
    int tens;
    int ones;
    char *result;
    int curIndex;
    static char *onesString[20] = {"zero", "one", "two", "three", "four",
	"five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve",
	"thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen",
	"nineteen"};
    static char *tensString[10] = {"units", "tens", "twenty", "thirty",
	"forty", "fifty", "sixty", "seventy", "eighty", "ninety"};

    if (value < 0 || value > 999) {
	return (char *)NULL;
    }

    result = (char *)ckalloc(sizeof(char) * MAX_NUM_STRING_LENGTH);
    result[0] = '\0';
    curIndex = 0;

    hundreds = (int) (value / 100);
    value = value - hundreds*100;

    tens = (int) (value / 10);
    if (tens == 1) {
	tens = 0;
    }
    value -= tens*10;

    ones = value;

    if (hundreds) {
	strcpy(result, onesString[hundreds]);
	curIndex = curIndex + strlen(onesString[hundreds]);
	strcpy(result+curIndex, " hundred");
	curIndex = curIndex + 8;
    }
    if (tens) {
	if (hundreds) {
	    *(result+curIndex) = ' ';
	    curIndex++;
	}
	strcpy(result+curIndex, tensString[tens]);
	curIndex = curIndex + strlen(tensString[tens]);
    }
    if (ones) {
	if (hundreds || tens) {
	    *(result+curIndex) = ' ';
	    curIndex++;
	}
	if (!hundreds && !tens) {
	    strcpy(result+curIndex, onesString[ones]);
	    curIndex = curIndex + strlen(onesString[ones]);
	} else {
	    strcpy(result+curIndex, onesString[ones]);
	    curIndex = curIndex + strlen(onesString[ones]);
	}
    }

    result[curIndex] = '\0';

    return result;
}
