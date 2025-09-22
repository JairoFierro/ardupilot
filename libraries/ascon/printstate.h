#pragma once

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

#ifdef __cplusplus
}
#endif