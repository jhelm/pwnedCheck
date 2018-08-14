/* pwnedCheck.c
 * V 0.0.0 - John Helm, 12 Aug 2018
 *
 * pwnedCheck uses SHA1 code published in RFC 3174, which conveys this copyright
 *
 *   Copyright (C) The Internet Society (2001).  All Rights Reserved.
 *
 *   This document and translations of it may be copied and furnished to
 *   others, and derivative works that comment on or otherwise explain it
 *   or assist in its implementation may be prepared, copied, published
 *   and distributed, in whole or in part, without restriction of any
 *   kind, provided that the above copyright notice and this paragraph are
 *   included on all such copies and derivative works.  However, this
 *   document itself may not be modified in any way, such as by removing
 *   the copyright notice or references to the Internet Society or other
 *   Internet organizations, except as needed for the purpose of
 *   developing Internet standards in which case the procedures for
 *   copyrights defined in the Internet Standards process must be
 *   followed, or as required to translate it into languages other than
 *   English.
 *
 *   The limited permissions granted above are perpetual and will not be
 *   revoked by the Internet Society or its successors or assigns.
 *
 *   This document and the information contained herein is provided on an
 *   "AS IS" basis and THE INTERNET SOCIETY AND THE INTERNET ENGINEERING
 *   TASK FORCE DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING
 *   BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION
 *   HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * pwnedCheck is covered by the MIT license
 *
 *   Copyright 2018 John Helm
 * 
 *   Permission is hereby granted, free of charge, to any person obtaining
 *   a copy of this software and associated documentation files (the
 *   "Software"), to deal in the Software without restriction, including
 *   without limitation the rights to use, copy, modify, merge, publish,
 *   distribute, sublicense, and/or sell copies of the Software, and to
 *   permit persons to whom the Software is furnished to do so, subject to
 *   the following conditions:
 * 
 *  The above copyright notices and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _PWNEDCHECK_H_
#define _PWNEDCHECK_H_

#define     PWNED_DIR            "./" 
#define     PWNED_FILENAME       "pwned-passwords-ordered-by-hash.txt" 
#define     FILE_NAME_MAX_SIZE   256
#define     FILE_BUFFER_SIZE     256             /* being lazy here...        */
#define     HASH_BUFFER_SIZE     256
#define     SHA1_SIZE             40

#include    <assert.h>                           /* for compile time checking */
#define static_assert _Static_assert
#include    <sys/types.h>
static_assert( sizeof(off_t) == 8, "This program must be compiled for 64 POSIX machines" );

#include    <stdio.h>
#include    <stdlib.h>
#include    <stdbool.h>
#include    <string.h>
#include    <stddef.h>
#include    <ctype.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <sys/stat.h>
#include    "sha1.h"

off_t          fileSizeGet   (int fileNo, struct stat *st, char *fileName);
off_t          binFileSearch (int fileNo, char *key, off_t fPosL, off_t fPosR, char brkChar, char eorChar); 
char          *getPwnedFspec (char *pwFileSpec, char *arg, char *pwPathDefault);
bool           parseArgs(int argc, char *argv[], bool *terseFlag, bool *sha1Flag, char *pwFileSpec, char* pwText);
bool           pswd2sha1(char *pswd, char *pwText);
void           helpMsg       (void);


#endif
