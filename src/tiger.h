/**
 * Copyright (c) 2012 Francisco Blas Izquierdo Riera (klondike)
 * The Tiger algorithm was written by Eli Biham and Ross Anderson and is
 * available on the official Tiger algorithm page.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    the algorithm authorsip notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 4. If this license is not appropriate for you please write me at
 *    klondike ( a t ) klondike ( d o t ) es to negotiate another license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **/

/**
 * These are some implementations of tiger made without looking at the original
 * reference code to ensure the resulting code can be published under a free
 * license. The paper was looked though to know how did tiger work.
 */

/** Implementation details:
 * * Here we assume char and unsigned char have size 1. If thats not the case in
 *     your compiler you may want to replace them by a type that does
 */

#ifndef TIGER_H
#define TIGER_H 1

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || (_MSC_VER >= 1600)
#include <stdint.h>
#else

typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#endif

#if _M_IX86_FP >= 2
#define __SSE2__
#endif

#ifdef __linux
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define IS_LITTLE_ENDIAN
#elif  __BYTE_ORDER == __BIG_ENDIAN
#define USE_BIG_ENDIAN
#elif  __BYTE_ORDER == __PDP_ENDIAN
#error "If you feel like writting code for PDP endianess go ahead, I'm not doing that"
#else
#error "Unknown endianess"
#endif
#else
//Assume little endian if you know how to detect endianism well on other
//compilers state it.
#define IS_LITTLE_ENDIAN
#endif

#if defined(_WIN64) || defined(__x86_64__) || defined(__amd64__)
#define HASX64
#endif


/** A word in the tiger hash, 64 bits **/
typedef uint64_t t_word;

/** This one is provided as a commodity for people wanting an easy way
 * to declare result variables **/
typedef t_word t_res[3];

/** Partial calculation as used by tigerp1 and tigerp2 **/
typedef struct {
	t_res h; // Hash status
	char r[128]; // SALT
	t_word n; // Number of characters of r used
	t_word hs; // Amount of total data hashed
} t_pres;

/** This one is provided as a commodity for people wanting an easy way
 * to declare block variables **/
typedef t_word t_block[8];

/** Standard tiger calculation, put your string in str and the string
 * length on length and get the result on res **/
void tiger (const char *str, t_word length, t_res res);
/** Similar to tiger but interleaving accesses to both equally sized
 * strings to reduce overhead and pipeline stalls you get the result of
 * str1 on res1 and the one of str2 on res2 **/
void tiger_2 (const char *str1, const char *str2, t_word length,
              t_res res1, t_res res2);
#ifdef __SSE2__
/** This is equivalent to tiger_2 but uses SSE2 for the key schduling
 * making it faster **/
void tiger_sse2 (const char *str1, const char *str2, t_word length,
                 t_res res1, t_res res2);
#endif
/** This function is optimized for use on TTHs just send the two
 * concatenated hashes and you will get back the hash with a prepended
 * 0x01 **/
void tiger_49 (const char *str, t_res res);
/** This function is optimized for use on TTHs just send the 1024 sized
 * block and you will get back the hash with a prepended 0x00 **/
void tiger_1025 (const char *str, t_res res);
/** Interleaved version of tiger_49 you insert two hashes and get back
 * two results **/
void tiger_2_49 (const char *str1, const char *str2,
                 t_res res1, t_res res2);
/** Interleaved version of tiger_1025 you insert two hashes and get
 * back two results **/
void tiger_2_1025 (const char *str1, const char *str2,
                   t_res res1, t_res res2);
#ifdef __SSE2__
/** SSE2 version of tiger_49 you insert two hashes and get back two
 * results **/
void tiger_sse2_49 (const char *str1, const char *str2,
                    t_res res1, t_res res2);
/** SSE2 version of tiger_1025 you insert two hashes and get back two
 * results **/
void tiger_sse2_1025 (const char *str1, const char *str2,
                      t_res res1, t_res res2);
#endif
/** First stage of partial tiger calculation to improve password
 * security during storage **/
void tigerp1 (const char *password, t_word length, const char *salt,
              t_pres *pres);
/** Second stage of partial tiger calculation **/
void tigerp2 (const t_pres *pres, const char *salt, t_word length,
              t_res res);

#ifdef __cplusplus
}  //extern "C"
#endif

#endif
