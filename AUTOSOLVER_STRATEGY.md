# Auto-Solver Strategy for Ciphertool

## Overview

This document outlines a comprehensive strategy for automatically identifying unknown cipher types and solving them using the existing ciphertool library.

## Core Technical Challenges

### 1. **Classification Ambiguity**
- Many cipher types produce similar statistical profiles (e.g., simple substitution vs. homophonic)
- Limited ciphertext length reduces classification confidence
- Some ciphers are composites (e.g., transposition + substitution)
- Period detection for polyalphabetic ciphers is non-trivial

### 2. **Feature Engineering Complexity**
- Need discriminative features across 40+ cipher types
- Features must work on short texts (ACA ciphers often <200 chars)
- Character distribution overlap between cipher families
- Period-dependent features for polyalphabetic ciphers

### 3. **Computational Constraints**
- Some ciphers have enormous keyspaces (e.g., route transposition: 48 types)
- Multi-stage solving (identify, then solve) doubles computation
- Need early rejection of incorrect cipher types
- Balance between accuracy and speed

### 4. **Solver Integration**
- Each cipher has different solving strategies (dictionary, hillclimb, brute force)
- Confidence thresholds for "solved" vary by cipher type
- Parameter estimation (period, key length) required before solving
- Need to try multiple parameter combinations

## ML/Statistical Approaches

### **Hierarchical Classification Strategy**

```
Level 1: Cipher Family (5-6 classes)
├─ Substitution (monoalphabetic)
├─ Polyalphabetic
├─ Transposition
├─ Fractionating
├─ Morse/Binary
└─ Polygraphic

Level 2: Specific Type within Family
Level 3: Parameter Estimation (period, key length, etc.)
```

### **Feature Set for Classification**

**Universal Features (all ciphers):**
- Index of Coincidence (IoC)
- Chi-squared statistic
- Entropy
- Character frequency distribution (26-dimensional)
- Digram/trigram frequency correlations
- Length of ciphertext
- Presence of spaces/punctuation
- Even/odd position IoC ratio
- Max/min/mean character frequencies

**Family-Specific Features:**
- **Periodic IoC** (multiple period lengths 2-20) → detects polyalphabetic
- **Kasiski examination** → period indicators
- **Digram patterns** → distinguishes playfair/bifid
- **Character set** (a-z, binary, dots/dashes) → morse/pollux/binary ciphers
- **Repeated substring analysis** → transposition vs substitution
- **Bigram distribution** → fractionating ciphers have flat distribution

### **ML Model Architecture**

**Option 1: Random Forest (Recommended for MVP)**
- Pros: Works well with small datasets, interpretable, fast
- Train on synthetic ciphers (easy to generate thousands)
- Each tree can specialize in different cipher families
- Built-in feature importance analysis

**Option 2: Neural Network (Future Enhancement)**
- 1D CNN on character sequences
- Multi-task learning: classify + predict parameters simultaneously
- Requires large training corpus (10K+ examples per cipher type)

**Option 3: Hybrid Rule-Based + ML**
- Hard rules for obvious cases (IoC > 0.065 → likely monoalphabetic)
- ML for ambiguous cases
- Fastest and most transparent

## Implementation Strategy

### **Phase 1: Foundation (Weeks 1-2)**

**New C API functions in stat.c:**
```c
double StatComputeIoC(const char *text);
double StatComputePeriodicIoC(const char *text, int period);
double StatComputeChiSquared(const char *text);
double StatComputeEntropy(const char *text);
void StatKasiskiExamine(const char *text, int *periods, double *scores);
```

**New Tcl command: `cipher identify`**
```tcl
cipher identify $ciphertext ?-return all|best? ?-threshold 0.8?
# Returns: {type score confidence params}
# e.g., {aristocrat 0.95 {}} or {vigenere 0.87 {period 7}}
```

### **Phase 2: Feature Extraction (Week 3)**

**New file: cipherIdentify.c**
```c
typedef struct CipherFeatures {
    double ioc;
    double periodicIoc[20];  // periods 2-20
    double chiSquared;
    double entropy;
    double charFreq[26];
    double digramFlattness;
    int kasiskiPeriods[5];
    // ... 30-40 total features
} CipherFeatures;

CipherFeatures* ExtractFeatures(const char *ct);
```

### **Phase 3: Classification Engine (Week 4)**

**Option A: Rule-Based (Ship in v1.0)**
Create decision tree in Tcl:
```tcl
# library/cipherIdentify.tcl
proc CipherIdentify::classifyByRules {features} {
    if {$features(ioc) > 0.065} {
        # Likely monoalphabetic
        if {$features(digramPatterns) > 0.5} {
            return {type aristocrat confidence 0.90}
        }
    } elseif {$features(ioc) < 0.045} {
        # Likely polyalphabetic or transposition
        set period [findBestPeriod $features(periodicIoc)]
        if {$period > 0} {
            return {type vigenere confidence 0.85 params {period $period}}
        } else {
            return {type columnar confidence 0.75}
        }
    }
    # ... more rules
}
```

**Option B: ML-Based (Future)**
- Generate training data using existing encode functions
- Export feature vectors to CSV
- Train scikit-learn RandomForest in Python
- Export model as C decision tree or call Python via subprocess

### **Phase 4: Auto-Solver Integration (Week 5)**

**New program: progs/autosolve**
```tcl
#!/usr/bin/env tclsh
# Usage: autosolve -file cipher.txt [-attempts 3] [-confidence 0.8]

proc autosolve {ciphertext} {
    # 1. Identify cipher type
    set candidates [cipher identify $ciphertext -return all]

    # 2. Try solving in confidence order
    foreach {type confidence params} $candidates {
        if {$confidence < $threshold} break

        puts "Attempting $type (confidence: $confidence)..."
        set result [trySolve $type $ciphertext $params]

        if {[isSolved $result]} {
            return $result
        }
    }
    return "Unable to solve"
}

proc trySolve {type ct params} {
    # Call existing solver with type-specific parameters
    set c [cipher create $type -ct $ct {*}$params]

    switch $type {
        aristocrat - caesar { return [solveSubstitution $c] }
        vigenere - beaufort { return [solvePolyalphabetic $c] }
        columnar - amsco { return [solveTransposition $c] }
        # ... dispatch to appropriate solver
    }
}
```

### **Phase 5: User Experience (Week 6)**

**CLI Interface:**
```bash
# Auto-identify only
$ ctool identify cipher.txt
Type: aristocrat (confidence: 0.93)
Alternative: patristocrat (confidence: 0.12)

# Auto-solve
$ ctool autosolve cipher.txt
Analyzing ciphertext...
Identified: aristocrat (0.93 confidence)
Solving...
Solution found in 2.3s:
  Key: QWERTYUIOPLKJHGFDSAZXCVBNM
  Plaintext: THE QUICK BROWN FOX...
  Score: 947.2

# Verbose mode
$ ctool autosolve cipher.txt -v
Features: IoC=0.067, Chi²=12.3, Entropy=4.1
Top candidates:
  1. aristocrat (0.93)
  2. vigenere (0.05)
  3. columnar (0.02)
Attempting aristocrat...
  Using wordtree solver
  Best score: 947.2 after 50000 iterations
  Confidence: SOLVED ✓
```

**Tcl API:**
```tcl
package require CipherIdentify

# Simple usage
set result [CipherIdentify::autosolve $ciphertext]

# Advanced usage
set identifier [CipherIdentify::create $ciphertext]
set types [$identifier getCandidates -threshold 0.7]
set solution [$identifier solve -attempts 5 -timeout 300]
```

## Training Data Strategy

Generate synthetic ciphers automatically:
```tcl
# progs/generateTrainingData
for {set i 0} {$i < 1000} {incr i} {
    set plaintext [getRandomEnglishText 100 300]

    foreach type [cipher types] {
        set c [cipher create $type]
        $c encode $plaintext [generateRandomKey $type]
        set ct [$c cget -ct]

        # Output: type, features, parameters
        puts "$type,[extractFeatures $ct],[getParams $c]"
    }
}
```

## Performance Optimizations

1. **Early rejection**: Compute cheap features first (IoC, length), eliminate impossible types
2. **Parallel solving**: Try top 3 candidates simultaneously (Tcl threads)
3. **Adaptive timeouts**: Longer for higher confidence types
4. **Feature caching**: Store computed features to avoid recomputation
5. **Type-specific heuristics**: Skip period detection for non-periodic ciphers

## Evaluation Metrics

Track accuracy on test corpus:
- **Top-1 accuracy**: Correct type is #1 prediction
- **Top-3 accuracy**: Correct type in top 3
- **Solve rate**: % of correctly identified ciphers that solve
- **Time-to-solution**: Performance metrics per cipher type
- **False positive rate**: Incorrectly identifying unsolvable text

## Recommended MVP Scope

**Include in v1.0:**
- Rule-based classifier for 10 most common ACA types (aristocrat, caesar, vigenere, columnar, playfair, beaufort, porta, railfence, route, bifid)
- `cipher identify` command with confidence scores
- `autosolve` program that chains identify → solve
- Period detection for polyalphabetic ciphers
- Basic feature extraction in C

**Defer to v2.0:**
- ML-based classification
- Composite cipher detection
- Automatic parameter tuning (e.g., hillclimb iterations)
- GUI integration
- Probabilistic scoring for "partially solved"

## Architecture Integration

This approach fits naturally into the existing codebase:

- **C layer (stat.c, new cipherIdentify.c)**: Low-level feature extraction and statistical analysis
- **Tcl layer (library/cipherIdentify.tcl)**: Classification logic and solver dispatch
- **Programs layer (progs/autosolve)**: User-facing CLI tool
- **Plugin architecture**: Each cipher type's existing `solveProc` is leveraged

The modular design allows incremental implementation and testing of individual components while maintaining backward compatibility with existing tools.
