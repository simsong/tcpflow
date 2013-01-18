/*
 * How do we do a template like this?
 */

#include <stdio.h>
#include <iostream>
#include <stdint.h>

template <typename T>
class A {
private:
    T var_;
    uint64_t count_;
public:
    A(T v):var_(v),count(0){ }
    uint64_t count() const { return count_;} 
    T var() const { return var_;}
    void inc_count();
};

template <typename T> void A<T>::inc_count() {
    count_++;
};

template <typename T> std::ostream & operator <<(std::ostream &os, const A<T> &e) {
    os << e.count() << "=" << e.var();
    return os;
};


int main(int argc,char **argv)
{
    A<int> a(3);

    a.inc_count();
    std::cout << a << "\n";
    
    a.inc_count();
    std::cout << a << "\n";

    
}
