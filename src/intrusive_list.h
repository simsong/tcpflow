#ifndef INTRUSIVE_LIST_H
#define INTRUSIVE_LIST_H

#include <iostream>
#include <list>

// implement boost::intrusive::list using std::list

template <class T>
class intrusive_list {
  public:
  intrusive_list():li(), len(0) {}
  
  typedef typename std::list<T*>::iterator iterator;
  
  inline void push_back(T* node) {
    li.push_back(node);
    len++;
    node->it = --li.end();
  }

  inline void erase(T* node) {
    if (!is_linked(node))
      return;
    li.erase(node->it);
    len--;
    reset(node);
  }
  
  inline void move_to_end(T* node) {
    if (!is_linked(node))
      return;
    li.splice(li.end(), li, node->it);
  }
  
  inline void reset(T* node) {
    node->it = li.end();
  }
  
  inline bool empty() {
    return li.empty();
  }
  
  inline size_t size() {
    // std::list.size() is O(n) in some platform. Is there any define flag for that?
    //return li.size();
    return len;
  }
  
  inline iterator begin() {
    return li.begin();
  }
  
  inline iterator end() {
    return li.end();
  }
  
  private:
  inline bool is_linked(T* node) {
    return node->it != li.end();
  }
  
  std::list<T*> li;
  size_t len;
};

#endif // INTRUSIVE_LIST_H
