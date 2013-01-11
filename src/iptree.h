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
    std::ostream & dump(std::ostream &os,int depth,uint32_t addr,const class node *ptr)const;
public:
    /* Service */
    static std::string ipv4(uint32_t addr);
    static bool bit(const uint8_t *addr,int i); // get the ith bit; 0 is the MSB
    
    /* copy is a deep copy */
    iptree(const iptree &n):root(n.root ? new node(*n.root) : 0),
                            nodes(n.nodes),
                            maxnodes(n.maxnodes){};

    iptree():root(new node(0)),nodes(0),maxnodes(maxnodes_default){};
    size_t size(){return nodes;};
    void add(const uint8_t *addr,size_t addrlen); // addrlen in bytes
    std::ostream & dump(std::ostream &os) const;
    int trim();                         // returns number trimmed, or 0
};

inline std::ostream & operator <<(std::ostream &os,const iptree &ipt) {
    return ipt.dump(os);
}

bool iptree::bit(const uint8_t *addr,int i)            // get the ith bit; 0 is MSB
{ 
    return (addr[i / 8]) & (1<<(7-i%8));
}


/* Currently assumes IPv4 */
void iptree::add(const uint8_t *addr,size_t addrlen)
{
    int maxdepth = addrlen * 8;         // in bits
    node *ptr = root;                  // start at the root
    for(int depth=0;depth<=maxdepth;depth++){
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

    inline std::string iptree::ipv4(uint32_t addr) 
{
    char buf[1024];
    snprintf(buf,sizeof(buf),"%d.%d.%d.%d",
             (addr & 0xff000000) >>24,
             (addr & 0x00ff0000) >> 16,
             (addr & 0x0000ff00) >> 8,
             (addr & 0x000000ff));
    return std::string(buf);
}


/** Find the best node to trim with a simple recursive
 * tree walking and voting algorithm
 *
 * The best node to trim is a terminal node that has
 * the lowest count 
 */
 
iptree::node *iptree::node_to_trim(iptree::node *ptr) const 
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
int iptree::trim()
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

std::ostream& iptree::dump(std::ostream &os) const
{
    os << "nodes: " << nodes << "\n";
    dump(os,0,0,root);
    os << "=====================\n";
    return os;
}

    /* Currently assumes ipv4 */
std::ostream&  iptree::dump(std::ostream& os,int depth,uint32_t addr,const node *ptr ) const
{
    if(ptr==0) return os;
    if(ptr->term) os << ptr << " is " << ipv4(addr) << "/" << depth << "   count=" << ptr->count << "\n";
    if(ptr->ptr0) dump(os,depth+1,addr,ptr->ptr0);
    if(ptr->ptr1) dump(os,depth+1,(addr | (1<<(31-depth))),ptr->ptr1);
    return os;
}

#endif
