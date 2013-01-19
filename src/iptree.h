/*
 * iptree.h:
 * 
 * Maintains a count of all IP addresses seen, with limits on the
 * maximum amount of memory.
 *
 */

/* TODO - cache addresses to nodes to avoid running the tree. */

#ifndef IPTREE_H
#define IPTREE_H

#include <stdint.h>
#include <algorithm>
#include <assert.h>
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>


/* addrbytes is the number of bytes in the address */

template <typename T,size_t ADDRBYTES> class iptreet {
private:;
    class not_impl: public std::exception {
	virtual const char *what() const throw() { return "copying tcpip objects is not implemented."; }
    };
    class node {
    private:
        /* Assignment is not implemented */
        node &operator=(const iptreet::node &that){
            throw not_impl();
        }
    public:
        class node *ptr0;               // 0 bit next
        class node *ptr1;               // 1 bit next
    private:
        uint64_t    tsum;               // this node and children
    public:
        /* copy is a deep copy */
        node(const iptreet::node &n):ptr0(n.ptr0 ? new node(*n.ptr0) : 0),
                                     ptr1(n.ptr1 ? new node(*n.ptr1) : 0),
                                     tsum(n.tsum) { }
        node():ptr0(0),ptr1(0),tsum(0){ }
        int children() const {return (ptr0 ? 1 : 0) + (ptr1 ? 1 : 0);}
        ~node(){
            if(ptr0){ delete ptr0; ptr0 = 0; }
            if(ptr1){ delete ptr1; ptr1 = 0; }
        };
        bool term() const {             // a node with no ptrs and a sum>0 is a terminal node
            return ptr0==0 && ptr1==0 && tsum>0;
        }
        int trim(class iptreet &tree){                    // trim this node
            /* Now delete those that we counted out */
            if(ptr0){
                assert(ptr0->term()); assert(ptr0->ptr0==0); assert(ptr0->ptr1==0);
                delete ptr0;
                ptr0=0;
                tree.nodes--;
            }
            if(ptr1){
                assert(ptr1->term()); assert(ptr1->ptr0==0); assert(ptr1->ptr1==0);
                delete ptr1;
                ptr1=0;
                tree.nodes--;
            }
            return 1;
        }
        /**
         * Return the best node to trim:
         * Possible outputs:
         * case 1 - no node (if this is a terminal node, it can't be trimmed; shoudl not have been called)
         * case 2 - this node (if all of the children are terminal)
         * case 3 - the best node of the one child (if there is only one child)
         * case 4 - the of the non-terminal child (if one child is terminal and one is not)
         * case 5 - the better node of each child's best node.
         */
        const node *best_to_trim(int *best_depth,int my_depth) const {
            assert(term()==0);
            if (ptr0 && !ptr1 && ptr0->term()) {*best_depth=my_depth;return this;} // case 2
            if (ptr1 && !ptr0 && ptr1->term()) {*best_depth=my_depth;return this;} // case 2
            if (ptr0 && ptr0->term() && ptr1 && ptr1->term()) {*best_depth=my_depth;return this;} // case 2
            if (ptr0 && !ptr1) return ptr0->best_to_trim(best_depth,my_depth+1); // case 3
            if (ptr1 && !ptr0) return ptr1->best_to_trim(best_depth,my_depth+1); // case 3

            if (ptr0->term() && !ptr1->term()) return ptr1->best_to_trim(best_depth,my_depth+1); // case 4
            if (ptr1->term() && !ptr0->term()) return ptr0->best_to_trim(best_depth,my_depth+1); // case 4

            // case 5 - the better node of each child's best node.
            int ptr0_best_depth = my_depth;
            const node *ptr0_best = ptr0->best_to_trim(&ptr0_best_depth,my_depth+1);
            assert(ptr0_best!=0);       // There must be a best node!

            int ptr1_best_depth = my_depth;
            const node *ptr1_best = ptr1->best_to_trim(&ptr1_best_depth,my_depth+1);
            assert(ptr1_best!=0);       // There must be a best node!

            // The better to trim of two children is the one with a lower sum.
            if(ptr0_best->sum() < ptr1_best->sum()) {*best_depth=ptr0_best_depth;return ptr0_best;}
            if(ptr1_best->sum() < ptr0_best->sum()) {*best_depth=ptr1_best_depth;return ptr1_best;}
            
            // If they are equal, it's the one that's deeper
            if(ptr0_best_depth > ptr1_best_depth) {*best_depth=ptr0_best_depth;return ptr0_best;}
            *best_depth = ptr1_best_depth;
            return ptr1_best;
        }
        uint64_t sum() const { return tsum; }
        void inc(uint64_t val) { tsum+=val;}           // increment

    };
    class node *root;                   //
    enum {root_depth=0};                // depth of the root node
    enum {maxnodes_default=10000};
    iptreet &operator=(const iptreet &that){throw not_impl();}
protected:
    size_t     nodes;                  // how many do we have?
    size_t     maxnodes;                // how many will we tolerate?

public:
    /* Returned in the histogram */

    // returns true if addr[4..15]==0
    static std::string itos(int n){
        char buf[64];
        snprintf(buf,sizeof(buf),"%d",n);
        return std::string(buf);
    }
    static bool isipv4(const uint8_t *addr,size_t addrlen) { 
        if(addrlen==4) return true;
        for(u_int i=4;i<addrlen;i++){
            if(addr[i]!=0) return false;
        }
        return true;
    }
    static std::string ipstr(const uint8_t *addr,size_t addrlen,size_t depth){
        if(isipv4(addr,addrlen)){
            return ipv4(addr) + (depth<32 ? (std::string("/") + itos(depth)) : "");
        } else {
            return ipv6(addr) + (depth<128 ? (std::string("/") + itos(depth)) : "");
        }
    }

    class addr_elem {
    public:
        addr_elem(const uint8_t *addr_,uint8_t depth_,int64_t count_):
            addr(),depth(depth_),count(count_){
            memcpy((void *)addr,addr_,sizeof(addr));
        }
        addr_elem() : addr(), depth(0), count(0) {
            memset((void *) addr, 0x00, sizeof(addr));
        }
        addr_elem &operator=(const addr_elem &n){
            memcpy((void *)this->addr,n.addr,sizeof(this->addr));
            this->count = n.count;
            this->depth = n.depth;
            return *this;
        }
        virtual ~addr_elem(){}
        const uint8_t addr[ADDRBYTES];         // maximum size address; v4 addresses have addr[4..15]=0
        uint8_t depth;                  // in bits; /depth
        int64_t count;
        
        bool is4() const { return isipv4(addr,ADDRBYTES);};
        std::string str() const { return ipstr(addr,ADDRBYTES,depth); }
    };

    /* static service routines for displaying ipv4 and ipv6 addresses  */
    static std::string ipv4(const uint8_t *a){
        char buf[1024];
        snprintf(buf,sizeof(buf),"%d.%d.%d.%d",a[0],a[1],a[2],a[3]);
        return std::string(buf);
    }
    static std::string ipv6(const uint8_t *a){ 
        char buf[128];
        return std::string(inet_ntop(AF_INET6,a,buf,sizeof(buf)));
    }
    /* get the ith bit; 0 is the MSB */
    static bool bit(const uint8_t *addr,size_t i){
        return (addr[i / 8]) & (1<<(7-i%8));
    }
    /* set the ith bit to 1 */
    static void setbit(uint8_t *addr,size_t i){
        addr[i / 8] |= (1<<(7-i%8));
    }
    
    virtual ~iptreet(){}                // required per compiler warnings
    /* copy is a deep copy */
    iptreet(const iptreet &n):root(n.root ? new node(*n.root) : 0),
                              nodes(n.nodes),maxnodes(n.maxnodes){};

    /* create an empty tree */
    iptreet():root(new node()),nodes(0),maxnodes(maxnodes_default){};

    /* trim the tree, starting at the root. Find the node to trim and then trim it.
     * node that best_to_trim() returns a const pointer. But we want to modify it, so we
     * do a const_cast (which is completely fine).
     */
    int trim(){
        if(root->term()) return 0;        // terminal nodes can't be trimmed
        int tdepth=0;
        node *tnode = const_cast<node *>(root->best_to_trim(&tdepth,root_depth));
        return tnode ? tnode->trim(*this) : 0;
    }

    /* Simple implementation to trim the table to 90% of limit if at limit. Subclass to change behavior. */
    void trim_if_greater(size_t limit){
        if(nodes>=maxnodes){
            while(nodes > maxnodes * 9 / 10){ 
                if(trim()==0) break;         
            }
        }
    }


    /* add a node; implementation below */
    void add(const uint8_t *addr,size_t addrlen,uint64_t val); 
    void add(const uint8_t *addr,size_t addrlen){ add(addr,addrlen,1); }

    /* size the tree; the number of nodes */
    size_t size() const {return nodes;};

    /* sum the tree; the total number of adds that have been performed */
    uint64_t sum() const {return root->sum();};

    /* get a histogram of the tree, and starting at a particular node 
     * The histogram that is reported are only the terminal nodes.
     */
    typedef vector<addr_elem> histogram_t;
    void get_histogram(int depth,const uint8_t *addr,const class node *ptr,histogram_t  &histogram) const{
        if(ptr->term()){
            histogram.push_back(addr_elem(addr,depth,ptr->sum()));
            return;
        }
        if(depth>128) return;               // can't go deeper than this now
        
        /* create address with 0 and 1 added */
        uint8_t addr0[ADDRBYTES];
        uint8_t addr1[ADDRBYTES];
        
        memset(addr0,0,sizeof(addr0)); memcpy(addr0,addr,(depth+7)/8);
        memset(addr1,0,sizeof(addr1)); memcpy(addr1,addr,(depth+7)/8); setbit(addr1,depth);
        
        if(ptr->ptr0) get_histogram(depth+1,addr0,ptr->ptr0,histogram);
        if(ptr->ptr1) get_histogram(depth+1,addr1,ptr->ptr1,histogram);
    }
        
    void get_histogram(histogram_t &histogram) const { // adds the histogram to the passed in vector
        uint8_t addr[ADDRBYTES];
        memset(addr,0,sizeof(addr));
        get_histogram(0,addr,root,histogram);
    }

    /* dump the tree; largely for debugging */
    std::ostream & dump(std::ostream &os) const {
        histogram_t histogram;
        get_histogram(histogram);
        os << "nodes: " << nodes << "  histogram size: " << histogram.size() << "\n";
        for(size_t i=0;i<histogram.size();i++){
            os << histogram.at(i).str() << "  count=" << histogram.at(i).count << "\n";
        }
        return os;
    }
};


/* add a node.
 */ 
template <typename T,size_t ADDRBYTES> void iptreet<T,ADDRBYTES>::add(const uint8_t *addr,size_t addrlen,uint64_t val)
{
    trim_if_greater(maxnodes);
    if(addrlen > ADDRBYTES) addrlen=ADDRBYTES;

    u_int maxdepth = addrlen * 8;         // in bits
    node *ptr = root;                   // start at the root
    for(u_int depth=0;depth<=maxdepth;depth++){
        ptr->inc(val);                // increment this node (and all of its descendants 
        if(depth==maxdepth){        // reached bottom
            assert((ptr->ptr0==0) && (ptr->ptr1==0));
            return;                 // we are a terminal node; return
        }
        /* Not a terminal node, so go down a level based on the next bit,
         * extending if necessary.
         */
        if(bit(addr,depth)==0){
            if(ptr->ptr0==0){
                ptr->ptr0 = new node();
                nodes++;
            }
            ptr = ptr->ptr0;
        } else {
            if(ptr->ptr1==0){
                ptr->ptr1 = new node(); 
                nodes++;
            }
            ptr = ptr->ptr1;
        }
    }
    assert(0);                          // should never happen
}


/* a structure for a pair of IP addresses */
class ip2tree:public iptreet<uint64_t,32> {
public:
    /* de-interleave a pair of addresses */
    static void un_pair(uint8_t *addr1,uint8_t *addr2,size_t addr12len,size_t *depth1,size_t *depth2,const uint8_t *addr,size_t addrlen,size_t depth){
        for(size_t i=0;i<addrlen*8/2;i++){
            if(iptreet<uint64_t,32>::bit(addr,i*2))   iptreet<uint64_t,32>::setbit(addr1,i);
            if(iptreet<uint64_t,32>::bit(addr,i*2+1)) iptreet<uint64_t,32>::setbit(addr2,i);
        }
        *depth1 = (depth+1)/2;
        *depth2 = (depth)/2;
    }

    ip2tree(){}
    virtual ~ip2tree(){};
    /* str requires more work */
    static std::string ip2str(const uint8_t *addr,size_t addrlen,size_t depth){
        uint8_t addr1[16];memset(addr1,0,sizeof(addr1));
        uint8_t addr2[16];memset(addr2,0,sizeof(addr2));
        size_t depth1=0,depth2=0;
        ip2tree::un_pair(addr1,addr2,sizeof(addr1),&depth1,&depth2,addr,addrlen,depth);
        return ipstr(addr1,sizeof(addr1),depth1) + " " + ipstr(addr2,sizeof(addr2),depth2);
    }

    /* 2tree needs its own dump because a different ipstr is called */
    std::ostream & dump(std::ostream &os) const {
        histogram_t histogram;
        get_histogram(histogram);
        os << "nodes: " << nodes << "  histogram size: " << histogram.size() << "\n";
        for(size_t i=0;i<histogram.size();i++){
            const addr_elem &a = histogram.at(i);
            os << ip2str(a.addr,sizeof(a.addr),a.depth) << "  count=" << histogram.at(i).count << "\n";
        }
        return os;
    }

    /* Add a pair of addresses by interleaving them */
    void add_pair(const uint8_t *addr1,const uint8_t *addr2,size_t addrlen){
        uint8_t addr[32];
        memset(addr,0,sizeof(addr));
        /* Interleave on the bit by bit level */
        for(size_t i=0;i<addrlen*8;i++){
            if(iptreet<uint64_t,32>::bit(addr1,i)) iptreet<uint64_t,32>::setbit(addr,i*2);
            if(iptreet<uint64_t,32>::bit(addr2,i)) iptreet<uint64_t,32>::setbit(addr,i*2+1);
        }
        add(addr,addrlen*2); /* Add it */
    }

};

typedef iptreet<uint64_t,16> iptree;       // simple tree for counting; reimplement so val is tcount
template <typename T,size_t ADDRBYTES> std::ostream & operator <<(std::ostream &os,const iptreet<T,ADDRBYTES> &ipt) {
    return ipt.dump(os);
}

inline std::ostream & operator <<(std::ostream &os,const ip2tree &ipt) {
    return ipt.dump(os);
}


#endif
