/*
 * iptree.h:
 * 
 * Maintains a count of all IP addresses seen, with limits on the
 * maximum amount of memory.
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
        node(const iptree::node &):ptr0(0),ptr1(0),trimmed(false),count(0){ throw not_impl();}
        node &operator=(const iptree::node &that){ throw not_impl();}
    public:
        node():ptr0(0),ptr1(0),trimmed(false),count(0){ }
        virtual ~node(){
            if(ptr0){
                count += ptr0->count;
                delete ptr0;
                ptr0 = 0;
            }
            if(ptr1){
                count += ptr1->count;
                delete ptr1;
                ptr1 = 0;
            }
        };
        class node *ptr0;               // 0 bit next
        class node *ptr1;               // 1 bit next
        bool trimmed;                    // tree below was trimmed
        uint64_t count;                 // this and children
    };
    class node *root;               //
    size_t     nodes;
    size_t     maxnodes;                    // how many will we tolerate?
    enum {maxnodes_default=10000};
public:
    iptree():root(new node()),nodes(1),maxnodes(maxnodes_default){};
    size_t size(){return nodes;};
    void add(const class ipaddr &ip);
    void dump(int depth,uint32_t addr,const class node *ptr)const;
    void dump() const{
        std::cerr << "nodes: " << nodes << "\n";
        dump(0,0,root);
        std::cerr << "=====================\n";
    };
};

/* Currently assumes IPv4 */
void iptree::add(const class ipaddr &ip)
{
    node *ptr = root;                  // start at the root
    for(int depth=0;depth<33;depth++){
        ptr->count++;                  // increment this node
        if(depth==32 || ptr->trimmed){
            return;                     // we found the last node. Go home.
        }
        bool bit = ip.bit(depth);
        if(bit==0){
            if(ptr->ptr0==0){
                nodes++;
                ptr->ptr0 = new node();
            }
            ptr = ptr->ptr0;
        } else {
            if(ptr->ptr1==0){
                nodes++;
                ptr->ptr1 = new node();
            }
            ptr = ptr->ptr1;
        }
    }
    assert(0);                          // should never happen
}

void iptree::dump(int depth,uint32_t addr,const node *ptr ) const
{
    if(ptr==0) return;
    fprintf(stderr,"%d.%d.%d.%d/%d   count=%"PRIu64"\n",
            (addr & 0xff000000)>>24,
            (addr & 0x00ff0000)>>16,
            (addr & 0x0000ff00)>>8,
            (addr & 0x000000ff)>>0,
            depth,
            ptr->count);
    if(ptr->ptr0) dump(depth+1,addr,ptr->ptr0);
    if(ptr->ptr1) dump(depth+1,(addr | (1<<(31-depth))),ptr->ptr1);
}

#endif
