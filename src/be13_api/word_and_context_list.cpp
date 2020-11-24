/**
 * class word_and_context_list reads from disk and maintains in memory
 * a data structure that is used for the stop list and alert list.
 */

#include "config.h"
#include <sys/types.h>
#include <inttypes.h>
#include "word_and_context_list.h"
#include "beregex.h"

void word_and_context_list::add_regex(const std::string &pat)
{
    patterns.push_back(new beregex(pat,0));
}

/**
 * Insert a feature and context, but only if not already present.
 * Returns true if added.
 */
bool word_and_context_list::add_fc(const std::string &f,const std::string &c)
{
    context ctx(f,c);			// ctx includes feature, before and after

    if(c.size()>0 && context_set.find(c) != context_set.end()) return false; // already present
    context_set.insert(c);		// now we've seen it.
    fcmap.insert(std::pair<std::string,context>(f,ctx));
    //if(fcmap.size()%100==0) std::cerr << "fcmap size=" << fcmap.size()  << "\n";
    return true;
}

/** returns 0 if success, -1 if fail. */
int word_and_context_list::readfile(const std::string &filename)
{
    std::ifstream i(filename.c_str());
    if(!i.is_open()) return -1;
    printf("Reading context stop list %s\n",filename.c_str());
    std::string line;
    uint64_t total_context=0;
    uint64_t line_counter = 0;
    uint64_t features_read = 0;
    while(getline(i,line)){
	line_counter++;
	if(line.size()==0) continue;
	if(line[0]=='#') continue; // it's a comment
	if((*line.end())=='\r'){
	    line.erase(line.end());	/* remove the last character if it is a \r */
	}
	if(line.size()==0) continue;	// no line content
	++features_read;

	// If there are two tabs, this is a line from a feature file
	size_t tab1 = line.find('\t');
	if(tab1!=std::string::npos){
	    size_t tab2 = line.find('\t',tab1+1);
	    if(tab2!=std::string::npos){
		size_t tab3 = line.find('\t',tab2+1);
		if(tab3==std::string::npos) tab3=line.size();
                std::string f = line.substr(tab1+1,(tab2-1)-tab1);
                std::string c = line.substr(tab2+1,(tab3-1)-tab2);
		if(add_fc(f,c)){
		    ++total_context;
		}
	    } else {
                std::string f = line.substr(tab1+1);
		add_fc(f,"");		// Insert a feature with no context
	    }
	    continue;
	}

	// If there is no tab, then this must be a simple item to ignore.
	// If it is a regular expression, add it to the list of REs
	if(beregex::is_regex(line)){
	    patterns.push_back(new beregex(line,REG_ICASE));
	} else {
	    // Otherwise, add it as a feature with no context
	    fcmap.insert(std::pair<std::string,context>(line,context(line)));
	}
    }
    std::cout << "Stop list read.\n";
    std::cout << "  Total features read: " << features_read << "\n";
    std::cout << "  List Size: " << fcmap.size() << "\n";
    std::cout << "  Context Strings: " << total_context << "\n";
    std::cout << "  Regular Expressions: " << patterns.size() << "\n";
    return 0;
}

/** check() is threadsafe. */
bool word_and_context_list::check(const std::string &probe,const std::string &before,const std::string &after) const
{
    /* First check literals, because they are faster */
    for(stopmap_t::const_iterator it =fcmap.find(probe);it!=fcmap.end();it++){
	if((rstrcmp((*it).second.before,before)==0) &&
	   (rstrcmp((*it).second.after,after)==0) &&
	   ((*it).second.feature==probe)){
	    return true;
	}
    }

    /* Now check the patterns; do this second */
    for(beregex_vector::const_iterator it=patterns.begin(); it != patterns.end(); it++){
	if((*it)->search(probe,0,0,0)){
	    return true;		// yep
	}
    }
    return false;
};

bool word_and_context_list::check_feature_context(const std::string &probe,const std::string &context) const 
{
    std::string before;
    std::string after;
    context::extract_before_after(probe,context,before,after);
    return check(probe,before,after);
}

void word_and_context_list::dump()
{
    std::cout << "dump context list:\n";
    for(stopmap_t::const_iterator it =fcmap.begin();it!=fcmap.end();it++){
	std::cout << (*it).first << " = " << (*it).second << "\n";
    }
    std::cout << "dump RE list:\n";
    for(beregex_vector::const_iterator it=patterns.begin(); it != patterns.end(); it++){
	std::cout << (*it)->pat << "\n";
    }
}

#ifdef STAND
int  main(int argc,char **argv)
{
    cout << "testing contxt_list\n";
    word_and_context_list cl;
    while(--argc){
	argv++;
	if(cl.readfile(*argv)){
	    err(1,"Cannot read %s",*argv);
	}
    }
    cl.dump();
    exit(1);
}
#endif
