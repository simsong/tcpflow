/*
 * iptree.h:
 * 
 * Maintains a count of all IP addresses seen, with limits on the
 * maximum amount of memory.
 *
 * TK - Remove the vector; trim by walking the tree. We're doing it already
 */

#ifndef IPTREE_H
#define IPTREE_H

#include <stdint.h>
#include <algorithm>
#include <assert.h>
#include <iostream>


/* template <class Type> */ class iptree {
private:;
    class not_impl: public std::exception {
	virtual const char *what() const throw() { return "copying tcpip objects is not implemented."; }
    };
    class node {
    private:
        /* Assignment is not implemented */
        node &operator=(const iptree::node &that){
            throw not_impl();
        }
    public:
        /* copy is a deep copy */
        node(const iptree::node &n):ptr0(n.ptr0 ? new node(*n.ptr0) : 0),
                                    ptr1(n.ptr1 ? new node(*n.ptr1) : 0),
                                    term(n.term),
                                    count(n.count),
                                    tcount(n.tcount) { }
        node():ptr0(0),ptr1(0),term(false),count(0),tcount(0){ }
        int children() const {return (ptr0 ? 1 : 0) + (ptr1 ? 1 : 0);}
        ~node(){
            if(ptr0){
                delete ptr0;
                ptr0 = 0;
            }
            if(ptr1){
                delete ptr1;
                ptr1 = 0;
            }
        };
        void trim(class iptree &tree){                    // trim this node
            assert(tcount==0);            // we should have no children yet
            term = true;

            /* Sum each of the children into the node and then delete them */
            if(ptr0){
                tcount += ptr0->tcount;
                assert(ptr0->term);
                assert(ptr0->ptr0==0);
                assert(ptr0->ptr1==0);
                delete ptr0;
                ptr0=0;
                tree.nodes--;
            }
            if(ptr1){
                tcount += ptr1->tcount;
                assert(ptr1->term);
                assert(ptr1->ptr0==0);
                assert(ptr1->ptr1==0);
                delete ptr1;
                ptr1=0;
                tree.nodes--;
            }
            // at this point, tcount==count, right?
            assert(tcount==count);
        }
        class node *ptr0;               // 0 bit next
        class node *ptr1;               // 1 bit next
        bool  term;                    // terminal node
        uint64_t count;                 // this and children
        uint64_t tcount;                 // this node
    };
    class node *root;                   //
    enum {root_depth=0};                // depth of the root node
    size_t     nodes;                  // how many do we have?
    size_t     maxnodes;                // how many will we tolerate?
    enum {maxnodes_default=10000};
    iptree &operator=(const iptree &that){throw not_impl();}
    node *node_to_trim(int *tdepth,node *ptr,size_t ptr_depth) const;
public:
    /* Returned in the histogram */
    class addr_elem {
    public:
        addr_elem(const uint8_t *addr_,uint8_t depth_,int64_t count_):
            addr(),depth(depth_),count(count_){
            memcpy((void *)addr,addr_,sizeof(addr));
        }
        addr_elem &operator=(const addr_elem &n){
            memcpy((void *)this->addr,n.addr,sizeof(this->addr));
            this->count = n.count;
            this->depth = n.depth;
            return *this;
        }
        ~addr_elem(){}
        const uint8_t addr[16];         // maximum size address
        uint8_t depth;                  // in bits; /depth
        int64_t count;
    };

    /* Service */
    static std::string ipv4(const uint8_t *addr);
    static bool bit(const uint8_t *addr,size_t i); // get the ith bit; 0 is the MSB
    static void setbit(uint8_t *addr,size_t i); // setst the ith bit to 1
    
    /* copy is a deep copy */
    iptree(const iptree &n):root(n.root ? new node(*n.root) : 0),
                            nodes(n.nodes),
                            maxnodes(n.maxnodes){};

    iptree():root(new node()),nodes(0),maxnodes(maxnodes_default){};
    size_t size(){return nodes;};
    void add(const uint8_t *addr,size_t addrlen); // addrlen in bytes
    int trim();                 // returns number trimmed, or 0
    std::ostream & dump(std::ostream &os) const;

    void get_histogram(int depth,const uint8_t *addr,const class node *ptr,vector<addr_elem> &histogram)const;
    void get_histogram(vector<addr_elem> &histogram) const; // adds the histogram to the passed in vector
};

inline std::ostream & operator <<(std::ostream &os,const iptree &ipt) {
    return ipt.dump(os);
}

inline bool iptree::bit(const uint8_t *addr,size_t i) // get the ith bit; 0 is MSB
{ 
    return (addr[i / 8]) & (1<<(7-i%8));
}

void iptree::setbit(uint8_t *addr,size_t i) // sets the bit to 1
{ 
    addr[i / 8] |= (1<<(7-i%8));
}


/* Currently assumes IPv4 */
inline void iptree::add(const uint8_t *addr,size_t addrlen)
{
    /* trim the tree if it is too big */
    if(nodes>=maxnodes){
        while(nodes > maxnodes * 9 / 10){ // trim 10% of the nodes
            if(trim()==0) break;          // can't trim anymore
        }
    }

    u_int maxdepth = addrlen * 8;         // in bits
    node *ptr = root;                   // start at the root
    for(u_int depth=0;depth<=maxdepth;depth++){
        ptr->count++;               // increment this node
        if(depth==maxdepth){        // reached bottom
            ptr->term = 1;
        }
        if(ptr->term){                  // if this is a terminal node
            ptr->tcount++;              // increase terminal count
            assert(ptr->ptr0==0);
            assert(ptr->ptr1==0);
            return;                     // we found a terminal node. stop
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

inline std::string iptree::ipv4(const uint8_t *a) 
{
    char buf[1024];
    snprintf(buf,sizeof(buf),"%d.%d.%d.%d",a[0],a[1],a[2],a[3]);
    return std::string(buf);
}


/** Find the best node to trim with a simple recursive
 * tree walking and voting algorithm
 *
 * The best node to trim is a terminal node that has
 * the lowest count 
 */
 
inline iptree::node *iptree::node_to_trim(int *tdepth,iptree::node *ptr,size_t ptr_depth) const 
{
    if(ptr->term) return 0;           // can't trim a terminal node, only its parent

    /* If we are not terminal, both ptr0 and ptr1 can't be null */
    assert(ptr->ptr0!=0 || ptr->ptr1!=0);

    /* If one branch is null and the other is not...
     * Return this node if the other is terminal, otherwise return that node's node_to_trim().
     */
    if(ptr->ptr0==0 && ptr->ptr1){
        if(ptr->ptr1->term) {*tdepth=ptr_depth;return ptr;}
        return node_to_trim(tdepth,ptr->ptr1,ptr_depth+1);
    }
    if(ptr->ptr1==0 && ptr->ptr0){
        if(ptr->ptr0->term) {*tdepth=ptr_depth;return ptr;}
        return node_to_trim(tdepth,ptr->ptr0,ptr_depth+1);
    }

    /* If we are here, then both must be non-null */
    assert(ptr->ptr0!=0 && ptr->ptr1!=0);

    /* If both children are terminal, this is the node to trim */
    if(ptr->ptr0->term && ptr->ptr1->term) {*tdepth=ptr_depth;return ptr;}

    /* If one is terminal and the other isn't, this node can't be trimmed.
     * Return the trim of the one that isn't
     */
    if(ptr->ptr0->term==0 && ptr->ptr1->term!=0) return node_to_trim(tdepth,ptr->ptr0,ptr_depth+1);
    if(ptr->ptr1->term==0 && ptr->ptr0->term!=0) return node_to_trim(tdepth,ptr->ptr1,ptr_depth+1);

    /* Both are not leafs, so check them both and return the better*/
    int tnode0_depth=0,tnode1_depth=0;
    node *tnode0 = node_to_trim(&tnode0_depth,ptr->ptr0,ptr_depth+1);
    node *tnode1 = node_to_trim(&tnode1_depth,ptr->ptr1,ptr_depth+1);

    if(tnode0==0 && tnode1==0) return 0; // can't trim either
    if(tnode0==0 && tnode1!=0) {*tdepth=tnode1_depth;return tnode1;} // can't trim 0, return 1
    if(tnode0!=0 && tnode1==0) {*tdepth=tnode0_depth;return tnode0;} // can't trim 1, return 0
    
    /* Term the node with the lower count or, if they are the same, the node with the higher depth */
    if ((tnode0->count < tnode1->count) ||
        ((tnode0->count==tnode1->count) && (tnode0_depth > tnode1_depth))){
        *tdepth=tnode0_depth;
        return tnode0;
    } else {
        *tdepth=tnode1_depth;
        return tnode1;
    }
}

/** Find the smallest element and term it.
 */
inline int iptree::trim()
{
    int tdepth=0;
    node *tdel = node_to_trim(&tdepth,root,root_depth);    // node to trim
    if(tdel==0) return 0;                 // nothing can be trimmed

    // Make sure that the tree is consistent
    //assert(tdel->depth == tdepth);        // for testing

    // Make sure that the nodes below the node being trimmed are terminal
    //assert(tdel->ptr0==0 || tdel->ptr0->term);
    //assert(tdel->ptr1==0 || tdel->ptr1->term);

    // Trim the node's children
    tdel->trim(*this);                       // trim this node
    return 1;
}

/* The histogram that is reported are only the terminal nodes. */

inline void iptree::get_histogram(int depth,const uint8_t *addr,
                                  const node *ptr,vector<addr_elem> &histogram) const
{
    //printf("ptr->depth=%d  depth=%d\n",ptr->depth,depth);
    //assert(ptr->depth==depth);
    if(ptr->term){
        histogram.push_back(addr_elem(addr,depth,ptr->tcount));
        return;
    }
    if(depth>128) return;               // can't go deeper than this now

    /* create address with 0 and 1 added */
    uint8_t addr0[16];
    uint8_t addr1[16];

    memset(addr0,0,sizeof(addr0)); memcpy(addr0,addr,(depth+7)/8);
    memset(addr1,0,sizeof(addr1)); memcpy(addr1,addr,(depth+7)/8); setbit(addr1,depth);

    if(ptr->ptr0) get_histogram(depth+1,addr0,ptr->ptr0,histogram);
    if(ptr->ptr1) get_histogram(depth+1,addr1,ptr->ptr1,histogram);
}

    /* Currently assumes ipv4 */
inline void iptree::get_histogram(vector<addr_elem> &histogram) const
{
    uint8_t addr[16];
    memset(addr,0,sizeof(addr));
    get_histogram(0,addr,root,histogram);
}

inline std::ostream& iptree::dump(std::ostream &os) const
{
    vector<addr_elem> histogram;
    get_histogram(histogram);
    os << "nodes: " << nodes << "  histogram size: " << histogram.size() << "\n";
    for(vector<addr_elem>::const_iterator it=histogram.begin();it!=histogram.end();it++){
        os << ipv4((*it).addr) << "/" << (int)((*it).depth) << "  count=" << (*it).count << "\n";
    }
    return os;
}

#endif
