/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef _CPACK_H
#define _CPACK_H


#include <sys/types.h>
#include <inttypes.h>

struct cpack_state {
    u_int8_t *c_buf;
    u_int8_t *c_next;
    size_t   c_len;
};

int cpack_init(struct cpack_state *, uint8_t *, size_t);

int cpack_uint8(struct cpack_state *, uint8_t *);
int cpack_uint16(struct cpack_state *, uint16_t *);
int cpack_uint32(struct cpack_state *, uint32_t *);
int cpack_uint64(struct cpack_state *, uint64_t *);

inline int cpack_int8(struct cpack_state *s, int8_t *p) {return cpack_uint8(s,(uint8_t *)p);}
inline int cpack_int16(struct cpack_state *s, int16_t *p) {return cpack_uint16(s,(uint16_t *)p);}
inline int cpack_int32(struct cpack_state *s, int32_t *p) {return cpack_uint32(s,(uint32_t *)p);}
inline int cpack_int64(struct cpack_state *s, int64_t *p) {return cpack_uint64(s,(uint64_t *)p);}


#endif /* _CPACK_H */
