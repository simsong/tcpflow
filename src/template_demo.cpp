/*
 * How do we do a template like this?
 */

#include <stdio.h>
#include <iostream>

template <typename T>
class A {
    public:
    T var;
    A(T v):var(v){ }
    void inc();

};

template <typename T> void A<T>::inc() {
    var++;
};

template <typename T> std::ostream & operator <<(std::ostream &os, const A<T> &e) {
    os << e.var;
    return os;
};


int main(int argc,char **argv)
{
    A<int> a(3);

    a.inc();
    std::cout << a << "\n";
    
    a.inc();
    std::cout << a << "\n";

    
}
