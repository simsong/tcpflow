#ifndef HISTOGRAM_H
#define HISTOGRAM_H

/**
 * \addtogroup internal_interfaces
 * @{
 */

/* C++ Histogram classes.
 *
 * Eventually this may become a single class
 */

#include <vector>
#include <map>

/**
 * \class CharClass
 * Examine a block of text and count the number of characters
 * in various ranges. This is useful for determining if a block of
 * bytes is coded in BASE16, BASE64, etc.
 */

class CharClass {
public:
    uint32_t range_0_9;			// a range_0_9 character
    uint32_t range_A_Fi;		// a-f or A-F
    uint32_t range_g_z;			// g-z
    uint32_t range_G_Z;			// G-Z
    CharClass():range_0_9(0),range_A_Fi(0),range_g_z(0),range_G_Z(0){
    }
    void add(uint8_t ch){
	if(ch>='a' && ch<='f') range_A_Fi++;
	if(ch>='A' && ch<='F') range_A_Fi++;
	if(ch>='g' && ch<='z') range_g_z++;
	if(ch>='G' && ch<='Z') range_G_Z++;
	if(ch>='0' && ch<='9') range_0_9++;
    }
    void add(uint8_t *buf,size_t len){
	for(size_t i=0;i<len;i++){
	    add(buf[i]);
	}
    }
};


/**
 * \file histogram.h
 * Unicode histogram
 *
 * The basis of a string-based correlator and many other features.
 * Uses C++ STL for sorting and string handling.
 * 
 * Summer 2011: Now is UTF-8/UTF-16 aware. All strings are stored as UTF-8.
 * Detects UTF-16 in an add and automatically converts to UTF-8.
 * Keeps track of UTF-16 count separately from UTF-8 count.
 *
 * Oct 2011: Apparently you are not supposed to subclass the STL container classes. 
 */
		

class HistogramMaker  {
public:
    static const int FLAG_LOWERCASE= 0x01;
    static const int FLAG_NUMERIC  = 0x02;                    // digits only
    static uint32_t debug_histogram_malloc_fail_frequency;    // for debugging, make malloc fail sometimes

    /** The ReportElement is used for creating the report of histogram frequencies.
     * It can be thought of as the histogram bin.
     */
    class histogramTally {
    public:
	uint32_t count;		// total strings seen
	uint32_t count16;	// total utf16 strings seen
	histogramTally():count(0),count16(0){};
	virtual ~histogramTally(){};
    };

    /** The ReportElement is used for creating the report of histogram frequencies.
     * It can be thought of as the histogram bin.
     */
    struct ReportElement {
	ReportElement(std::string aValue,histogramTally aTally):value(aValue),tally(aTally){ }
	const std::string   value;		// UTF-8
	histogramTally      tally;
	static bool compare_ref(const ReportElement &e1,const ReportElement &e2) {
	    if (e1.tally.count > e2.tally.count) return true;
	    if (e1.tally.count < e2.tally.count) return false;
	    return e1.value < e2.value;
	}
	static bool compare(const ReportElement *e1,const ReportElement *e2) {
	    if (e1->tally.count > e2->tally.count) return true;
	    if (e1->tally.count < e2->tally.count) return false;
	    return e1->value < e2->value;
	}
	virtual ~ReportElement(){};
    };

private:
    /** A HistogramMap holds the histogram while it is being computed.
     */
    typedef std::map<std::string,histogramTally> HistogramMap;
    HistogramMap h;			// holds the histogram
    uint32_t     flags;			// see above
public:

    /**
     * Determine if a string probably has utf16.
     */
    static bool looks_like_utf16(const std::string &str,bool &little_endian); 

    /* These all allocate a string that must be freed */

    static std::string *convert_utf16_to_utf8(const std::string &str);
    static std::string *convert_utf16_to_utf8(const std::string &str,bool little_endian);
    static std::string *make_utf8(const std::string &key);

    HistogramMaker(uint32_t flags_):h(),flags(flags_){}
    void clear(){h.clear();}
    void add(const std::string &key);	// adds a string to the histogram count

    /** A FrequencyReportVector is a vector of report elements when the report is generated.
     */
    typedef std::vector<ReportElement *> FrequencyReportVector;
    /** makeReport() makes a report and returns a
     * FrequencyReportVector.
     */
    FrequencyReportVector *makeReport() const;	// return a report with all of them
    FrequencyReportVector *makeReport(int topN) const; // returns just the topN
    virtual ~HistogramMaker(){};
};

std::ostream & operator <<(std::ostream &os,const HistogramMaker::FrequencyReportVector &rep);

#endif
