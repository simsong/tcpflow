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
        node(const iptree::node &):ptr0(0),ptr1(0),depth(),term(false),count(0){ throw not_impl();}
        node &operator=(const iptree::node &that){ throw not_impl();}
    public:
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
    iptree(const iptree &that):root(),nodes(),maxnodes(maxnodes_default){};
    iptree &operator=(const iptree &that){throw not_impl();}
    node *node_to_trim(node *ptr) const;
public:
    iptree():root(new node(0)),nodes(0),maxnodes(maxnodes_default){};
    size_t size(){return nodes;};
    void add(const class ipaddr &ip,sa_family_t family);
    void dump(int depth,uint32_t addr,const class node *ptr)const;
    void dump() const{
        std::cout << "nodes: " << nodes << "\n";
        dump(0,0,root);
        std::cout << "=====================\n";
    };
    void trim();
};

/* Currently assumes IPv4 */
void iptree::add(const class ipaddr &ip,sa_family_t family)
{
    int maxdepth = family==AF_INET6 ? 128 : 32;
    node *ptr = root;                  // start at the root
    for(int depth=0;depth<=maxdepth;depth++){
        ptr->count++;                  // increment this node
        if(depth==maxdepth){          // this is the bottom
            ptr->term = 1;
        }
        if(ptr->term) return;      // we found a terminal node. stop
        bool bit = ip.bit(depth);
        if(bit==0){
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

inline std::string ipv4(uint32_t addr) 
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

    /* this algorithm is symmetric for ptr0 and 1...*/
    for(int i=0;i<2;i++){
        node *a = (i==0) ? ptr->ptr0 : ptr->ptr1;
        node *b = (i==0) ? ptr->ptr1 : ptr->ptr0;

        /* If one branch is null and the other is not, return
         * the other if it is terminal, otherwise return the other's node_to_trim().
         */
        if(a==0 && b!=0){
            if(b->term) return ptr;
            return node_to_trim(b);
        }
    }

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
    return (tnode0->count < tnode1->count) ? tnode0 : tnode1;

}


/** Find the smallest element and term it.
 */
void iptree::trim()
{
    node *tdel = node_to_trim(root);    // node to trim
    printf("root=%p tdel=%p\n",root,tdel);
    if(tdel==0) return;                 // nothing can be trimmed
    if(tdel==root) assert(tdel->ptr0!=0 || tdel->ptr1!=0);

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
    return;
}

void iptree::dump(int depth,uint32_t addr,const node *ptr ) const
{
    if(ptr==0) return;
    if(ptr->term) std::cout << ptr << " is " << ipv4(addr) << "/" << depth << "   count=" << ptr->count << "\n";
    if(ptr->ptr0) dump(depth+1,addr,ptr->ptr0);
    if(ptr->ptr1) dump(depth+1,(addr | (1<<(31-depth))),ptr->ptr1);
}

#endif
