# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Ciphertool is a Tcl extension for working with classical cryptographic ciphers. It provides tools for displaying, manipulating, analyzing, and solving various cipher types used in the American Cryptogram Association (ACA). The codebase is written in C and interfaces with Tcl/Tk for scripting and GUI capabilities.

## Code Branching

IMPORTANT: Before you make any change, create and checkout a feature branch named "feature_some_short_name" based off of the master branch.  Make and then commit your changes in this branch.

## Build System

This project uses autoconf/automake for configuration:

```bash
# Configure the build (first time or after configuration changes)
./configure

# Build the library and binaries
make

# Build all components including package, binaries, and documentation
make all

# Run tests
make test

# Run tests with memory leak checking (requires valgrind)
make memtest

# Generate HTML documentation
make doc

# Install the package
make install
```

## Testing

Tests are located in the `tests/` directory and use the Tcl tcltest framework:

```bash
# Run all tests
make test

# Run a specific test file directly
tclsh tests/aristocrat.test

# Run tests with specific tcltest flags
make test TESTFLAGS="-match pattern*"
```

After making any changes to existing C or Tcl code, you must run the test suite with no test failures.

If you add any new C or Tcl code, you must write new unit tests to exercise all lines in the new code.  Run the test suite against the code to ensure that it passes.

## Project Structure

### Core Architecture

The codebase follows a modular plugin architecture where each cipher type is implemented as a separate module that registers itself with the central cipher system:

- **cipher.h / cipher.c / cipherInit.c**: Core cipher framework that defines the `CipherType` structure. Each cipher type implements a set of function pointers (createProc, deleteProc, cmdProc, decipherProc, etc.) that are registered via `InitCiphertypes()`.

- **score.h / score.c**: Pluggable scoring system for evaluating plaintext quality. Multiple scoring methods are supported (digram, trigram, n-gram, wordtree) using a similar plugin pattern with `ScoreType` structures.

- **Cipher implementations** (amsco.c, aristocrat.c, bifid.c, etc.): Each file implements a specific cipher type by providing the required function pointers defined in `CipherType`. All cipher modules follow the same structure pattern.

### Key Components

- **hillclimb.c/h**: Hill-climbing optimization algorithms used by cipher solvers to find optimal keys through iterative improvement.

- **dictionary.c/h, wordtree.c/h**: Word pattern matching and dictionary lookup facilities. The wordtree structure provides efficient pattern searching for automated solving.

- **keygen.c/h**: Key generation utilities for creating valid cipher keys.

- **solver.c/h**: Standalone recursive solver for substitution ciphers using dictionary-based pattern matching.

- **stat.c/h, digram.c/h**: Statistical analysis tools for frequency analysis and digram scoring.

### Tcl Integration

The C code exposes Tcl commands that are used by higher-level Tcl scripts:

- **library/*.tcl**: Tcl scripts that provide solver implementations and utilities. These use the C commands created in cipherInit.c.

- **progs/**: Executable Tcl scripts for specific cipher-solving tasks (e.g., `csolve`, `hillclimb`, `nicsolve`). These are the primary user-facing tools.

- **tclAppInit.c / tkAppInit.c**: Entry points for standalone Tcl/Tk applications.

## Adding New Cipher Types

To add a new cipher type:

1. Create a new .c file following the pattern of existing cipher implementations (e.g., aristocrat.c)
2. Implement all required function pointers from the `CipherType` structure in cipher.h
3. Add the new cipher type to `InitCiphertypes()` in cipher.c
4. Add the .c file to `GENERIC_OBJECTS` in Makefile.in
5. Create corresponding test file in tests/ directory

## Language/Encoding Requirements

- Valid characters are typically defined per cipher type (see `valid_chars` in `CipherType`)
- Most ciphers work with lowercase a-z, some support extended character sets
- Text extraction functions (`ExtractValidChars`, `TextToInt`) handle character validation
- The `IsValidChar` function in cipherUtil.c validates characters against the cipher's alphabet

## Data Files

- **data/**: Sample cipher texts for testing
- **library/*Data.tcl**: Pre-computed frequency tables (digrams, trigrams, n-grams) used for scoring
- **englishFrequencies.h**: C header with English language frequency data
- **wordlist**: Dictionary file for pattern matching

## Important Constants

- Route transposition types are numbered 1-48 (defined in cipher.h as NW_ROW_X_ROW, etc.)
- Scoring methods include digram count/log, trigram count/log, n-gram, and wordtree
- DEFAULT_DICTIONARY_LOCATION is set during configure and compiled into the binary
