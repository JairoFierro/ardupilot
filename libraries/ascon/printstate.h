#pragma once

#include "ascon.h"

#ifdef __cplusplus
extern "C" {
#endif

// Debug print functions - empty implementations for release builds
static inline void print(const char* text) { (void)text; }
static inline void printbytes(const char* text, const unsigned char* x, unsigned long long xlen) { 
    (void)text; (void)x; (void)xlen; 
}
static inline void printword(const char* text, const unsigned long long x) { 
    (void)text; (void)x; 
}
static inline void printstate(const char* text, const ascon_state_t* s) {
    (void)text; (void)s;
}

#ifdef __cplusplus
}
#endif