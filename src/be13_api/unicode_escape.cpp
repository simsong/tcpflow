/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/**
 * unicode_escape.cpp:
 * Escape unicode that is not valid.
 * 
 * References:
 * http://www.ietf.org/rfc/rfc3987.txt
 * http://en.wikipedia.org/wiki/UTF-8
 *
 * @author Simson Garfinkel
 *
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software
 * bears no warranty, either expressed or implied. NPS does not assume
 * legal liability nor responsibility for a User's use of the software
 * or the results of such use.
 *
 * Please note that within the United States, copyright protection,
 * under Section 105 of the United States Code, Title 17, is not
 * available for any work of the United States Government and/or for
 * any works created by United States Government employees. User
 * acknowledges that this software contains work which was created by
 * NPS government employees and is therefore in the public domain and
 * not subject to copyright.
 */

#ifndef PACKAGE_NAME
#include "config.h"
#endif

#include "unicode_escape.h"

#include <stdio.h>
#include <assert.h>
#include <iostream>
#include <fstream>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#define IS_IN_RANGE(c, f, l)    (((c) >= (f)) && ((c) <= (l)))

#include "utf8.h"

//extern int debug;

std::string hexesc(unsigned char ch)
{
    char buf[10];
    snprintf(buf,sizeof(buf),"\\x%02X",ch);
    return std::string(buf);
}

/** returns true if this is a UTF8 continuation character */
bool utf8cont(unsigned char ch)
{
    return ((ch&0x80)==0x80) &&  ((ch & 0x40)==0);
}

/**
 * After a UTF-8 sequence is decided, this function is called
 * to determine if the character is invalid. The UTF-8 spec now
 * says that if a UTF-8 decoding produces an invalid character, or
 * a surrogate, it is not valid. (There were some nasty security
 * vulnerabilities that were exploited before this came out.)
 * So we do a lot of checks here.
 */
bool valid_utf8codepoint(uint32_t unichar)
{
    // Check for invalid characters in the bmp
    switch(unichar){
    case 0xfffe: return false;          // reversed BOM
    case 0xffff: return false;
    default:
        break;
    }
    if(unichar >= 0xd800 && unichar <=0xdfff) return false; // high and low surrogates
    if(unichar < 0x10000) return true;  // looks like it is in the BMP

    // check some regions outside the bmp

    // Plane 1:
    if(unichar > 0x13fff && unichar < 0x16000) return false;
    if(unichar > 0x16fff && unichar < 0x1b000) return false;
    if(unichar > 0x1bfff && unichar < 0x1d000) return false;
        
    // Plane 2
    if(unichar > 0x2bfff && unichar < 0x2f000) return false;
    
    // Planes 3--13 are unassigned
    if(unichar >= 0x30000 && unichar < 0xdffff) return false;

    // Above Plane 16 is invalid
    if(unichar > 0x10FFFF) return false;        // above plane 16?
    
    return true;                        // must be valid
}

/**
 * validateOrEscapeUTF8
 * Input: UTF8 string (possibly corrupt)
 * Input: do_escape, indicating whether invalid encodings shall be escaped.
 * Note:
 *    - if not escaping but an invalid encoding is present and DEBUG_PEDANTIC is set, then assert() is called.
 *    - DO NOT USE wchar_t because it is 16-bits on Windows and 32-bits on Unix.
 * Output: 
 *   - UTF8 string.  If do_escape is set, then corruptions are escaped in \xFF notation where FF is a hex character.
 */

//int count=0;
bool validateOrEscapeUTF8_validate=false;
std::string validateOrEscapeUTF8(const std::string &input, bool escape_bad_utf8,bool escape_backslash)
{
    // 
    // skip the validation if not escaping and not DEBUG_PEDANTIC
    if (escape_bad_utf8==false && escape_backslash==false && !validateOrEscapeUTF8_validate){
        return input;
    }
        
    // validate or escape input
    std::string output;
    for(std::string::size_type i =0; i< input.length(); ) {
        uint8_t ch = (uint8_t)input.at(i);
        
        // utf8 1 byte prefix (0xxx xxxx)
        if((ch & 0x80)==0x00){          // 00 .. 0x7f
            if(ch=='\\' && escape_backslash){   // escape the escape character as \x92
                output += hexesc(ch);
                i++;
                continue;
            }

            if( ch < ' '){              // not printable are escaped
                output += hexesc(ch);
                i++;
                continue;
            }
            output += ch;               // printable is not escaped
            i++;
            continue;
        }

        // utf8 2 bytes  (110x xxxx) prefix
        if(((ch & 0xe0)==0xc0)  // 2-byte prefix
           && (i+1 < input.length())
           && utf8cont((uint8_t)input.at(i+1))){
            uint32_t unichar = (((uint8_t)input.at(i) & 0x1f) << 6) | (((uint8_t)input.at(i+1) & 0x3f));

            // check for valid 2-byte encoding
            if(valid_utf8codepoint(unichar)
               && ((uint8_t)input.at(i)!=0xc0)
               && (unichar >= 0x80)){ 
                output += (uint8_t)input.at(i++);       // byte1
                output += (uint8_t)input.at(i++);       // byte2
                continue;
            }
        }
                
        // utf8 3 bytes (1110 xxxx prefix)
        if(((ch & 0xf0) == 0xe0)
           && (i+2 < input.length())
           && utf8cont((uint8_t)input.at(i+1))
           && utf8cont((uint8_t)input.at(i+2))){
            uint32_t unichar = (((uint8_t)input.at(i) & 0x0f) << 12)
                | (((uint8_t)input.at(i+1) & 0x3f) << 6)
                | (((uint8_t)input.at(i+2) & 0x3f));
            
            // check for a valid 3-byte code point
            if(valid_utf8codepoint(unichar)
               && unichar>=0x800){                     
                output += (uint8_t)input.at(i++);       // byte1
                output += (uint8_t)input.at(i++);       // byte2
                output += (uint8_t)input.at(i++);       // byte3
                continue;
            }
        }
            
        // utf8 4 bytes (1111 0xxx prefix)
        if((( ch & 0xf8) == 0xf0)
           && (i+3 < input.length())
           && utf8cont((uint8_t)input.at(i+1))
           && utf8cont((uint8_t)input.at(i+2))
           && utf8cont((uint8_t)input.at(i+3))){
            uint32_t unichar =( (((uint8_t)input.at(i) & 0x07) << 18)
                                |(((uint8_t)input.at(i+1) & 0x3f) << 12)
                                |(((uint8_t)input.at(i+2) & 0x3f) <<  6)
                                |(((uint8_t)input.at(i+3) & 0x3f)));

            if(valid_utf8codepoint(unichar) && unichar>=0x1000000){
                output += (uint8_t)input.at(i++);       // byte1
                output += (uint8_t)input.at(i++);       // byte2
                output += (uint8_t)input.at(i++);       // byte3
                output += (uint8_t)input.at(i++);       // byte4
                continue;
            }
        }

        if (escape_bad_utf8) {
            // Just escape the next byte and carry on
            output += hexesc((uint8_t)input.at(i++));
        } else {
            // fatal if we are debug pedantic, otherwise just ignore
            // note: we shouldn't be here anyway, since if we are not escaping and we are not
            // pedantic we should have returned above
            if(validateOrEscapeUTF8_validate){
                std::ofstream os("bad_unicode.txt");
                os << input << "\n";
                os.close();
                std::cerr << "INTERNAL ERROR: bad unicode stored in bad_unicode.txt\n";
                assert(0);
            }
        }
    }
    return output;
}

#ifdef STANDALONE

void show(const std::string &ugly)
{
    for(size_t j=0;j<ugly.size();j++){
        printf("%02X ",(unsigned char)ugly[j]);
    }
}

void check(const std::string &ugly,bool verbose)
{
    std::string res = validateOrEscapeUTF8(ugly,true);
    std::wstring utf16;
    /* Now check to make sure it is valid UTF8 */
    try {
        utf8::utf8to16(res.begin(),res.end(),std::back_inserter(utf16));
        if(verbose){
            show(ugly);
            printf(" successfully encodes as ");
            show(res);
            printf(" (\"%s\")\n",res.c_str());
        }
    } catch(utf8::exception){
        printf("utf8 error hex sequence: ");
        show(ugly);
        printf(" encoded as: ");
        show(res);
        printf("\n");
    } catch(std::exception){
        std::cout << "other exception \n";
    }
}

void testfile(const char *fn)
{
    validateOrEscapeUTF8_validate = true;

    std::cout << "testing file " << fn << "\n";
    ifstream i(fn);
    if(i.is_open()){
        string line;
        getline(i,line);
        std::cout << "line length: " << line.size() << "\n";
        std::cout << "calling ValidateOrEscapeUTF8 to escape...\n";
        string l2 = validateOrEscapeUTF8(line,true);
        std::cout << "     length l2: " << l2.size() << "\n";
        std::cout << "calling ValidateOrEscapeUTF8 to validate...\n";
        validateOrEscapeUTF8(l2,false);
        std::cout << "calling check...\n";
        check(l2,false);
    }
    std::cout << "done\n";
    exit(0);
}

int main(int argc,char **argv)
{
    std::cout << "Unicode Escape Regression Tester\n";
    int ch;
    while ((ch = getopt(argc,argv,"r:h")) != -1){
        switch(ch) {
        case 'r':
            testfile(optarg);
            break;
        }
    }


    const char buf[] = {0xef, 0xbe, 0xad, 0x5c};
    check(std::string(buf,1),true);
    check(std::string(buf,2),true);
    check(std::string(buf,3),true);
    check(std::string(buf,4),true);

    /* Runs 16 copies simultaneously... */
    uint32_t max=0xFFFFFFFF;            // 2^32-1
    for(uint64_t prefix=0;prefix<max;prefix+=0x10000000){
        pid_t child = fork();
        if(child==0){
            /* Try all 4-byte sequences in the prefix range...*/
            for(uint32_t k=0;k<=0x0FFFFFFF;k++){
                uint32_t i=prefix+k;
                std::string ugly((char *)&i,4);
                check(ugly,false);
                if((i & 0x00FFFFFF)==0x00FFFFFF){
                    printf("pid=%d prefix=%x i=%x\n",getpid(),(uint32_t)prefix,(uint32_t)i);
                    fflush(stdout);
                }
            }
            exit(0);
        }
        printf("Launched PID %d\n",child);
        fflush(stdout);
    }
    for(int i=0;i<16;i++){
        int s=0;
        pid_t p = wait(&s);
        printf("pid %d finished with exit code %d\n",p,s);
    }
    std::cout << "done\n";
    exit(1);

    /* Generic fuzzing. Try random attempts */
    std::string line;
    while(getline(std::cin,line)){
        std::cout << validateOrEscapeUTF8(line,true) << "\n";
    }
        
}
#endif
