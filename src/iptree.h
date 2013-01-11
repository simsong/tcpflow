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

class iptree {
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
                                    depth(n.depth),
                                    term(n.term),
                                    count(n.count){ }
        node(int d):ptr0(0),ptr1(0),depth(d),term(false),count(0){ }
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
        class node *ptr0;               // 0 bit next
        class node *ptr1;               // 1 bit next
        uint8_t  depth;                 // not strictly needed, but makes things easier
        bool  term;                    // terminal node
        uint64_t count;                 // this and children
    };
    class node *root;                   //
    size_t     nodes;                  // how many do we have?
    size_t     maxnodes;                // how many will we tolerate?
    enum {maxnodes_default=10000};
    iptree &operator=(const iptree &that){throw not_impl();}
    node *node_to_trim(node *ptr) const;
public:
    class addr_elem {
    public:
        addr_elem(const uint8_t *addr_,uint8_t depth_,int64_t count_):addr(),depth(depth_),count(count_){
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

    iptree():root(new node(0)),nodes(0),maxnodes(maxnodes_default){};
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

    int maxdepth = addrlen * 8;         // in bits
    node *ptr = root;                  // start at the root
    for(int depth=1;depth<=maxdepth;depth++){
        ptr->count++;                  // increment this node
        if(depth==maxdepth){          // this is the bottom
            ptr->term = 1;
        }
        if(ptr->term) return;      // we found a terminal node. stop
        if(bit(addr,depth)==0){
            if(ptr->ptr0==0){
                ptr->ptr0 = new node(depth);
                nodes++;
            }
            ptr = ptr->ptr0;
        } else {
            if(ptr->ptr1==0){
                ptr->ptr1 = new node(depth); 
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
 
inline iptree::node *iptree::node_to_trim(iptree::node *ptr) const 
{
    if(ptr->term) return 0;           // can't trim a terminal node, only its parent

    /* If we are not terminal, both ptr0 and ptr1 can't be null */
    assert(ptr->ptr0!=0 || ptr->ptr1!=0);

    /* If one branch is null and the other is not, return
     * the other if it is terminal, otherwise return the other's node_to_trim().
     */
    if(ptr->ptr0==0 && ptr->ptr1) return (ptr->ptr1->term) ? ptr : node_to_trim(ptr->ptr1);
    if(ptr->ptr1==0 && ptr->ptr0) return (ptr->ptr0->term) ? ptr : node_to_trim(ptr->ptr0);

    /* If we are here, then both must be non-null */
    assert(ptr->ptr0!=0 && ptr->ptr1!=0);

    /* If both are terminal, then we are the one to trim */
    if(ptr->ptr0->term && ptr->ptr1->term) return ptr;

    /* If one is terminal and the other isn't, return the trim of the one that isn't */
    if(ptr->ptr0->term==0 && ptr->ptr1->term!=0) return node_to_trim(ptr->ptr0);
    if(ptr->ptr1->term==0 && ptr->ptr0->term!=0) return node_to_trim(ptr->ptr1);

    /* Both are not leafs, so check them both and return the better*/
    node *tnode0 = node_to_trim(ptr->ptr0);
    node *tnode1 = node_to_trim(ptr->ptr1);

    if(tnode0==0 && tnode1==0) return 0;
    if(tnode0==0 && tnode1!=0) return tnode1;
    if(tnode0!=0 && tnode1==0) return tnode0;
    
    /* determine if it is better to trim tnode0 or tnode1 */
    if (tnode0->count < tnode1->count) return tnode0;
    if (tnode0->count > tnode1->count) return tnode1;
    if (tnode0->depth > tnode1->count) return tnode0;
    return tnode1;
}


/** Find the smallest element and term it.
 */
inline int iptree::trim()
{
    node *tdel = node_to_trim(root);    // node to trim
    if(tdel==0) return 0;                 // nothing can be trimmed
    if(tdel==root) assert(tdel->ptr0!=0 || tdel->ptr1!=0); // double-che

    tdel->term = true;

    /* make sure that it's children are gone */
    if(tdel->ptr0){
        delete tdel->ptr0;
        tdel->ptr0=0;
        nodes--;
    }
    if(tdel->ptr1){
        delete tdel->ptr1;
        tdel->ptr1=0;
        nodes--;
    }
    return 1;
}

inline void iptree::get_histogram(int depth,const uint8_t *addr,const node *ptr,vector<addr_elem> &histogram) const
{
    //printf("ptr->depth=%d  depth=%d\n",ptr->depth,depth);
    assert(ptr->depth==depth);
    if(ptr->term){
        histogram.push_back(addr_elem(addr,depth,ptr->count));
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
