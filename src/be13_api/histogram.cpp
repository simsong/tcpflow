/**
 * histogram.cpp:
 * Maintain a histogram for Unicode strings provided as UTF-8 and UTF-16 encodings.
 * Track number of each coding provided.
 * 
 * TK: Reimplement top-n with a priority queue.
 *  http://www.cplusplus.com/reference/queue/priority_queue/
 */

#include "config.h"
#include "bulk_extractor_i.h"
#include "unicode_escape.h"
#include "histogram.h"
#include "utf8.h"

using namespace std;

ostream & operator << (ostream &os, const HistogramMaker::FrequencyReportVector &rep){
    for(HistogramMaker::FrequencyReportVector::const_iterator i = rep.begin(); i!=rep.end();i++){
        const HistogramMaker::ReportElement &r = *(*i);
	os << "n=" << r.tally.count << "\t" << validateOrEscapeUTF8(r.value, true, true);
	if(r.tally.count16>0) os << "\t(utf16=" << r.tally.count16<<")";
	os << "\n";
    }
    return os;
}

HistogramMaker::FrequencyReportVector *HistogramMaker::makeReport()  const
{
    FrequencyReportVector *rep = new FrequencyReportVector();
    for(HistogramMap::const_iterator it = h.begin(); it != h.end(); it++){
	rep->push_back(new ReportElement(it->first,it->second));
    }
    sort(rep->begin(),rep->end(),ReportElement::compare);
    return rep;
}

/* This would be better done with a priority queue */
HistogramMaker::FrequencyReportVector *HistogramMaker::makeReport(int topN) const
{
    HistogramMaker::FrequencyReportVector         *r2 = makeReport();	// gets a new report
    HistogramMaker::FrequencyReportVector::iterator i = r2->begin();
    while(topN>0 && i!=r2->end()){	// iterate through the first set
	i++;
	topN--;
    }

    /* Delete the elements we won't use */
    for(HistogramMaker::FrequencyReportVector::iterator j=i;j!=r2->end();j++){
        delete (*j);
    }
    r2->erase(i,r2->end());
    return r2;
}

/* static */
bool HistogramMaker::looks_like_utf16(const std::string &str,bool &little_endian)
{
    if((uint8_t)str[0]==0xff && (uint8_t)str[1]==0xfe){
	little_endian = true;
	return true; // begins with FFFE
    }
    if((uint8_t)str[0]==0xfe && (uint8_t)str[1]==0xff){
	little_endian = false;
	return true; // begins with FFFE
    }
    /* If none of the even characters are NULL and some of the odd characters are NULL, it's UTF-16 */
    uint32_t even_null_count = 0;
    uint32_t odd_null_count = 0;
    for(size_t i=0;i+1<str.size();i+=2){
	if(str[i]==0) even_null_count++;
	if(str[i+1]==0) odd_null_count++;
    }
    if(even_null_count==0 && odd_null_count>1){
	little_endian = true;
	return true;
    }
    if(odd_null_count==0 && even_null_count>1){
	little_endian = false;
	return true;
    }
    return false;
}

/**
 * Converts a utf16 with a byte order to utf8, returning an ALLOCATED STRING if conversion is
 * successful, and returning 0 if it is not.
 */
/* static */
std::string *HistogramMaker::convert_utf16_to_utf8(const std::string &key,bool little_endian)
{
    /* re-image this string as UTF16*/
    std::wstring utf16;
    for(size_t i=0;i<key.size();i+=2){
        if(little_endian) utf16.push_back(key[i] | (key[i+1]<<8));
        else utf16.push_back(key[i]<<8 | (key[i+1]));
    }
    /* Now convert it to a UTF-8;
     * set tempKey to be the utf-8 string that will be erased.
     */
    std::string *tempKey = new std::string;
    try {
        utf8::utf16to8(utf16.begin(),utf16.end(),std::back_inserter(*tempKey));
        /* Erase any nulls if present */
        while(tempKey->size()>0) {
            size_t nullpos = tempKey->find('\000');
            if(nullpos==string::npos) break;
            tempKey->erase(nullpos,1);
        }
    } catch(utf8::invalid_utf16){
        /* Exception; bad UTF16 encoding */
        delete tempKey;
        tempKey = 0;		// give up on temp key; otherwise its invalidated below
        return 0;
    }
    return tempKey;
}

std::string *HistogramMaker::convert_utf16_to_utf8(const std::string &key)
{
    bool little_endian=false;
    if(looks_like_utf16(key,little_endian)){
        return convert_utf16_to_utf8(key,little_endian);
    }
    return 0;
}

std::string *HistogramMaker::make_utf8(const std::string &key)
{
    std::string *utf8 = convert_utf16_to_utf8(key);
    if(utf8==0) utf8 = new std::string(key);
    return utf8;
}

/**
 * Takes a string (the key) and adds it to the histogram.
 * automatically determines if the key is UTF-16 and converts
 * it to UTF8 if so.
 */

uint32_t HistogramMaker::debug_histogram_malloc_fail_frequency = 0;
void HistogramMaker::add(const std::string &key)
{
    if(key.size()==0) return;		// don't deal with zero-length keys

    /**
     * "key" passed in is a const reference.
     * But we might want to change it. So keyToAdd points to what will be added.
     * If we need to change key, we allocate more memory, and make keyToAdd
     * point to the memory that was allocated. This way we only make a copy
     * if we need to make a copy.
     */

    const std::string *keyToAdd = &key;	// should be a reference, but that doesn't work
    std::string *tempKey = 0;		// place to hold UTF8 key
    bool found_utf16 = false;
    bool little_endian=false;
    if(looks_like_utf16(*keyToAdd,little_endian)){
        tempKey = convert_utf16_to_utf8(*keyToAdd,little_endian);
        if(tempKey){
            keyToAdd = tempKey;
            found_utf16 = true;
        }
    }
    
    /* If any conversion is necessary AND we have not converted key from UTF-16 to UTF-8,
     * then the original key is still in 'key'. Allocate tempKey and copy key to tempKey.
     */
    if(flags & (FLAG_LOWERCASE |FLAG_NUMERIC)){
	if(tempKey==0){
	    tempKey = new std::string(key);
	    keyToAdd = tempKey;
	}
    }


    /* Apply the flags */
    // See: http://stackoverflow.com/questions/1081456/wchar-t-vs-wint-t
    if(flags & FLAG_LOWERCASE){
	/* keyToAdd is UTF-8; convert to UTF-16, downcase, and convert back to UTF-8 */
	try{
	    std::wstring utf16key;
	    utf8::utf8to16(tempKey->begin(),tempKey->end(),std::back_inserter(utf16key));
	    for(std::wstring::iterator it = utf16key.begin();it!=utf16key.end();it++){
		*it = towlower(*it);
	    }
	    /* erase tempKey and copy the utf16 back into tempKey as utf8 */
	    tempKey->clear();		// erase the characters
	    utf8::utf16to8(utf16key.begin(),utf16key.end(),std::back_inserter(*tempKey));
	} catch(utf8::exception){
	    /* Exception thrown during utf8 or 16 conversions.
	     * So the string we thought was valid utf8 wasn't valid utf8 afterall.
	     * tempKey will remain unchanged.
	     */
	}
    }
    if(flags & FLAG_NUMERIC){
	/* keyToAdd is UTF-8; convert to UTF-16, extract digits, and convert back to UTF-8 */
	std::string originalTempKey(*tempKey);
	try{
	    std::wstring utf16key;
	    std::wstring utf16digits;
	    utf8::utf8to16(tempKey->begin(),tempKey->end(),std::back_inserter(utf16key));
	    for(std::wstring::iterator it = utf16key.begin();it!=utf16key.end();it++){
		if(iswdigit(*it) || *it==static_cast<uint16_t>('+')){
		    utf16digits.push_back(*it);
		}
	    }
	    /* convert it back */
	    tempKey->clear();		// erase the characters
	    utf8::utf16to8(utf16digits.begin(),utf16digits.end(),std::back_inserter(*tempKey));
	} catch(utf8::exception){
	    /* Exception during utf8 or 16 conversions*.
	     * So the string wasn't utf8.  Fall back to just extracting the digits
	     */
	    tempKey->clear();
	    for(std::string::iterator it = originalTempKey.begin(); it!=originalTempKey.end(); it++){
		if(isdigit(*it)){
		    tempKey->push_back(*it);
		}
	    }
	}
    }

    /* For debugging low-memory handling logic,
     * specify DEBUG_MALLOC_FAIL to make malloc occasionally fail
     */
    if(debug_histogram_malloc_fail_frequency){
	if((h.size() % debug_histogram_malloc_fail_frequency)==(debug_histogram_malloc_fail_frequency-1)){
	    throw bad_alloc();
	}
    }

    h[*keyToAdd].count++;
    if(found_utf16) h[*keyToAdd].count16++;  // track how many UTF16s were converted
    if(tempKey){			     // if we allocated tempKey, free it
	delete tempKey;
    }
}
    
