/*
 * adt_heap_type.h
 *
 *  Created on: 15Apr.,2017
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_ADT_MINHEAP_TYPE_H_
#define SRC_INCLUDE_ADT_MINHEAP_TYPE_H_


// Structure for a single heap entry
typedef struct heap_entry {
    void *key;   // Key for this entry
    void *value; // Value for this entry
} heap_entry;


// Main struct for representing the heap
typedef struct heap {
    int (*compare_func)(void*, void*); // The key comparison function to use
    int active_entries;  // The number of entries in the heap
    int minimum_pages;   // The minimum number of pages to maintain, based on the initial cap.
    int allocated_pages; // The number of pages in memory that are allocated
    int map_pages;       // The number of pages used for the map table
    void **mapping_table; // Pointer to the table, which maps to the pages
} heap;


#endif /* SRC_INCLUDE_ADT_MINHEAP_TYPE_H_ */
