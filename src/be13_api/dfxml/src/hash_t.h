/*
 * C++ covers for md5, sha1, and sha256 (and sha512 if present)
 *
 * hash representation classes: md5_t, sha1_t, sha256_t (sha512_t)
 * has generators: md5_generator(), sha1_generator(), sha256_generator()
 *
 * Generating a hash:
 * sha1_t val = sha1_generator::hash_buf(buf,bufsize)
 * sha1_t generator hasher;
 *       hasher.update(buf,bufsize)
 *       hasher.update(buf,bufsize)
 *       hasher.update(buf,bufsize)
 * sha1_t val = hasher.final()
 *
 * Using the values:
 * string val.hexdigest()   --- return a hext digest
 * val.size()		    --- the size of the hash in bytes
 * uint8_t val.digest[SIZE] --- the buffer of the raw bytes
 * uint8_t val.final()        --- synonym for md.digest
 *
 * This can be updated in the future for Mac so that the hash__ class
 * is then subclassed by a hash__openssl or a hash__commonCrypto class.
 *
 *
 * Revision History:
 * 2012 - Simson L. Garfinkel - Created for bulk_extractor.
 *
 * This file is public domain
 */

#ifndef  HASH_T_H
#define  HASH_T_H

#include <cstring>
#include <cstdlib>

/**
 * For reasons that defy explanation (at the moment), this is required.
 */


#ifdef __APPLE__
#include <AvailabilityMacros.h>
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER 
#define  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif

#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <unistd.h>

#if defined(HAVE_OPENSSL_HMAC_H) && defined(HAVE_OPENSSL_EVP_H)
#include <openssl/hmac.h>
#include <openssl/evp.h>
#else
#error OpenSSL required for hash_t.h
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYS_MMAP_H
#include <sys/mmap.h>
#endif

template<const EVP_MD *md(),size_t SIZE> 
class hash__
{
public:
    uint8_t digest[SIZE];
    static size_t size() {
        return(SIZE);
    }
    hash__(){
    }
    hash__(const uint8_t *provided){
	memcpy(this->digest,provided,size());
    }
    const uint8_t *final() const {
	return this->digest;
    }
    /* python like interface for hexdigest */
    static unsigned int hex2int(char ch){
	if(ch>='0' && ch<='9') return ch-'0';
	if(ch>='a' && ch<='f') return ch-'a'+10;
	if(ch>='A' && ch<='F') return ch-'A'+10;
	return 0;
    }
    static unsigned int hex2int(char ch0,char ch1){
        return (hex2int(ch0)<<4) | hex2int(ch1);
    }
    static hash__ fromhex(const std::string &hexbuf) {
	hash__ res;
        assert(hexbuf.size()==SIZE*2);
	for(unsigned int i=0;i+1<hexbuf.size() && (i/2)<size();i+=2){
	    res.digest[i/2] = hex2int(hexbuf[i],hexbuf[i+1]);
	}
	return res;
    }
    const char *hexdigest(char *hexbuf,size_t bufsize) const {
	const char *hexbuf_start = hexbuf;
	for(unsigned int i=0;i<SIZE && bufsize>=3;i++){
	    snprintf(hexbuf,bufsize,"%02x",this->digest[i]);
	    hexbuf  += 2;
	    bufsize -= 2;
	}
	return hexbuf_start;
    }
    std::string hexdigest() const {
	std::string ret;
	char buf[SIZE*2+1];
	return std::string(hexdigest(buf,sizeof(buf)));
    }
    /**
     * Convert a hex representation to binary, and return
     * the number of bits converted.
     * @param binbuf output buffer
     * @param binbuf_size size of output buffer in bytes.
     * @param hex    input buffer (in hex)
     * @return the number of converted bits.
     */
    static int hex2bin(uint8_t *binbuf,size_t binbuf_size,const char *hex)
    {
	int bits = 0;
	while(hex[0] && hex[1] && binbuf_size>0){
	    *binbuf++ = hex2int(hex[0],hex[1]);
	    hex  += 2;
	    bits += 8;
	    binbuf_size -= 1;
	}
	return bits;
    }
    static const hash__ *new_from_hex(const char *hex) {
	hash__ *val = new hash__();
	if(hex2bin(val->digest,sizeof(val->digest),hex)!=SIZE*8){
	    std::cerr << "invalid input " << hex << "(" << SIZE*8 << ")\n";
	    exit(1);
	}
	return val;
    }
    bool operator<(const hash__ &s2) const {
	/* Check the first byte manually as a performance hack */
	if(this->digest[0] < s2.digest[0]) return true;
	if(this->digest[0] > s2.digest[0]) return false;
	return memcmp(this->digest,s2.digest, SIZE) < 0;
    }
    bool operator==(const hash__ &s2) const {
	if(this->digest[0] != s2.digest[0]) return false;
	return memcmp(this->digest,s2.digest, SIZE) == 0;
    }
    friend std::ostream& operator<<(std::ostream& os,const hash__ &s2) {
        os << s2.hexdigest();
        return os;
    }
};

typedef hash__<EVP_md5,16> md5_t;
typedef hash__<EVP_sha1,20> sha1_t;
typedef hash__<EVP_sha256,32> sha256_t;
#ifdef HAVE_EVP_SHA512
typedef hash__<EVP_sha512,64> sha512_t;
#endif

template<typename T>
inline std::string digest_name();
template<>
inline std::string digest_name<md5_t>() {
    return "MD5";
}
template<>
inline std::string digest_name<sha1_t>() {
    return "SHA1";
}
template<>
inline std::string digest_name<sha256_t>() {
    return "SHA256";
}
#ifdef HAVE_EVP_SHA512
template<>
inline std::string digest_name<sha512_t>() {
    return "SHA512";
}
#endif

template<const EVP_MD *md(),size_t SIZE> 
class hash_generator__ { 			/* generates the hash */
 private:
    EVP_MD_CTX* mdctx;	     /* the context for computing the value */
    bool initialized;	       /* has the context been initialized? */
    bool finalized;
    /* Static function to determine if something is zero */
    static bool iszero(const uint8_t *buf,size_t bufsize){
	for(unsigned int i=0;i<bufsize;i++){
	    if(buf[i]!=0) return false;
	}
	return true;
    }
    /* Not allowed to copy; these are prototyped but not defined, so any attempt to use them will fail, but we won't get the -Weffc++ warnings  */
    hash_generator__ & operator=(const hash_generator__ &);
    hash_generator__(const hash_generator__ &);
public:
    int64_t hashed_bytes;
    /* This function takes advantage of the fact that different hash functions produce residues with different sizes */
    hash_generator__():mdctx(NULL),initialized(false),finalized(false),hashed_bytes(0){ }
    ~hash_generator__(){
	release();
    }
    void release(){			/* free allocated memory */
	if(initialized){
#ifdef HAVE_EVP_MD_CTX_FREE
	    EVP_MD_CTX_free(mdctx);
#else
	    EVP_MD_CTX_destroy(mdctx);
#endif
	    initialized = false;
	    hashed_bytes = 0;
	}
    }
    void init(){
	if(initialized==false){
#ifdef HAVE_EVP_MD_CTX_NEW
	    mdctx = EVP_MD_CTX_new();
#else
	    mdctx = EVP_MD_CTX_create();
#endif
            if (!mdctx) throw std::bad_alloc();
	    EVP_DigestInit_ex(mdctx, md(), NULL);
	    initialized = true;
	    finalized = false;
	    hashed_bytes = 0;
	}
    }
    void update(const uint8_t *buf,size_t bufsize){
	if(!initialized) init();
	if(finalized){
	    std::cerr << "hashgen_t::update called after finalized\n";
	    exit(1);
	}
	EVP_DigestUpdate(mdctx,buf,bufsize);
	hashed_bytes += bufsize;
    }
    hash__<md,SIZE> final() {
	if(finalized){
	  std::cerr << "currently friendly_geneator does not cache the final value\n";
	  assert(0);
          exit(1);                      // in case compiled with assertions disabled
	}
	if(!initialized){
	  init();			/* do it now! */
	}
	hash__<md,SIZE> val;
	unsigned int len = sizeof(val.digest);
	EVP_DigestFinal(mdctx,val.digest,&len);
	finalized = true;
	return val;
    }

    /** Compute a sha1 from a buffer and return the hash */
    static hash__<md,SIZE>  hash_buf(const uint8_t *buf,size_t bufsize){
	/* First time through find the SHA1 of 512 NULLs */
	hash_generator__ g;
	g.update(buf,bufsize);
	return g.final();
    }
	
#ifdef HAVE_MMAP
    /** Static method allocateor */
    static hash__<md,SIZE> hash_file(const char *fname){
	int fd = open(fname,O_RDONLY
#ifdef O_BINARY
		      |O_BINARY
#endif
		      );
	if(fd<0) throw fname;
	struct stat st;
	if(fstat(fd,&st)<0){
	    close(fd);
	    throw fname;
	}
	const uint8_t *buf = (const uint8_t *)mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd,0);
	if(buf==0){
	    close(fd);
	    throw fname;
	}
	hash__<md,SIZE> s = hash_buf(buf,st.st_size);
	munmap((void *)buf,st.st_size);
	close(fd);
	return s;
    }
#endif
};

typedef hash_generator__<EVP_md5,16> md5_generator;
typedef hash_generator__<EVP_sha1,20> sha1_generator;
typedef hash_generator__<EVP_sha256,32> sha256_generator;

#ifdef HAVE_EVP_SHA512
typedef hash_generator__<EVP_sha512,64> sha512_generator;
#define HAVE_SHA512_T
#endif

#endif
