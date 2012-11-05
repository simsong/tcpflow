/* MD5DEEP - md5.h
 *
 * By Jesse Kornblum
 *
 * This is a work of the US Government. In accordance with 17 USC 105,
 * copyright protection is not available for any work of the US Government.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Extended by Simson Garfinkel with a nice C++ API.
 */

/* $Id: md5.h 389 2011-07-10 19:03:02Z xchatty $ */

#ifndef __MD5_H
#define __MD5_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>	// for snprintf

/* __BEGIN_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names.  Use __END_DECLS at
   the end of C declarations. */
#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

// -------------------------------------------------------------- 
// After this is the algorithm itself. You shouldn't change these

__BEGIN_DECLS

typedef struct {
    uint32_t buf[4];
    uint32_t bits[2];
    unsigned char in[64];
} context_md5_t ;

#ifdef WIN32
// This is needed to make RSAREF happy on some MS-DOS compilers 
typedef context_md5_t MD5_CTX;
#endif

void MD5Init(context_md5_t *ctx);
void MD5Update(context_md5_t *context, const unsigned char *buf, size_t len);
void MD5Final(unsigned char digest[16], context_md5_t *context);
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);
__END_DECLS

#ifdef __cplusplus
#include <string.h>
#include <string>
/**
 * md5_t represents an md5 residue
 */
class md5_t{
    static const size_t SIZE=16;
public:
    uint8_t digest[SIZE];
    /* python like interface for hexdigest */
    const char *hexdigest(char *hexbuf,size_t bufsize) const {
	const char *hexbuf_start = hexbuf;
	for(unsigned int i=0;i<sizeof(digest) && bufsize>=3;i++){
	    snprintf(hexbuf,bufsize,"%02x",digest[i]);
	    hexbuf  += 2;
	    bufsize -= 2;
	}
	return hexbuf_start;
    }
    std::string hexdigest() const {
	std::string ret;
	char buf[sizeof(digest)*2+1];
	return std::string(hexdigest(buf,sizeof(buf)));
    }
    bool operator<(const md5_t &s2) const {
	/* Check the first byte manually as a performance hack */
	if(this->digest[0] < s2.digest[0]) return true;
	if(this->digest[0] > s2.digest[0]) return false;
	return memcmp(this->digest,s2.digest, this->SIZE) < 0;
    }
    bool operator==(const md5_t &s2) const {
	if(this->digest[0] != s2.digest[0]) return false;
	return memcmp(this->digest,s2.digest, this->SIZE) == 0;
    }
};

/**
 * md5_generator knows how to hash
 */
class md5_generator {
public:
    bool finalized;
    context_md5_t ctx;
    md5_generator():finalized(false),ctx(){
	MD5Init(&ctx);
    }
    void update(const uint8_t *buf,size_t buflen){
	assert(!finalized);
	MD5Update(&ctx,buf,buflen);
    }
    md5_t final(){
	md5_t res;
	assert(!finalized);
	MD5Final(res.digest,&ctx);
	finalized=true;
	return res;
    }
    static md5_t hash_buf(const uint8_t *buf,size_t buflen){
	md5_generator g;
	g.update(buf,buflen);
	return g.final();
    }
};
#endif

#endif /* ifndef __MD5_H */
