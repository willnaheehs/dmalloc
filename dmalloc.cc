#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <vector>
#include <string>
#include <iostream>

using namespace std;

// You may write code here.
// (Helper functions, types, structs, macros, globals, etc.)

// Task 1: Heap Usage Statistics
//  - Implement dmalloc_get_statistics() to track memory allocations
//  - Implement a structure to store Metadata for each allocation (size, file, line number)
//  - Use global stats to track overall statistics (active allocations, total allocations, total size)
//  - Implement dmalloc_malloc() and dmalloc_free() to modify statistics.
//  - tests 001–012.
// Task 2: Integer Overflow Protection
//  - Make dmalloc_calloc() handle integer overflow.
//  - Include checks for overflow (check if nmemb * sz exceeds SIZE_MAX).
//  - tests 013–015
// Task 3: Invalid Free and Double Free Detection
//  - Implement dmalloc_free() to handle invalid and double frees
//  - Track allocated pointers using a data structure (hash table?)
//  - Exits with an error message when invalid frees are detected
//  - tests 016–024
// Task 4: Boundary Write Error Detection
//  - Implement logic in dmalloc_malloc() that allocates extra space for boud checks
//  - Detect if any allocations occurr outside the allocated bounds? (dmalloc_free()?)
//  - Use canaries
//  - tests 025–027.
// Task 5: Memory Leak Reporting
//  - Implement dmalloc_print_leak_report()
//  - Metadata should store allocation pointer info?
//  - Traverse to print all unfreed allocations
//  - tests 028–030.
// Task 6: Advanced Reports and Checking
// Objective: Improve error detection and reporting for invalid frees
// - Error messages need to include info about where the invalid free happens
// - Check if pointer being freed is inside another valid block
// - tests 031–034 (edge cases and performance)

bool invalid_free_found = false;  // global flag used to not print stats if invalid free is found
unsigned long long heavy_hitters_size = 0;


// holds information about each allocation
struct Metadata {
    size_t allocation_size;
    const char* file;
    long line;
    uintptr_t magic_number; // magic number here to detect valid blocks
};

dmalloc_statistics global_stats = {
    0,  // nactive
    0,  // active_size
    0,  // ntotal
    0,  // total_size
    0,  // nfail
    0,  // fail_size
    (uintptr_t) -1,  // heap_min (set to max possible value initially)
    0   // heap_max
};

// magic number to help detect invalid memory operations
// store it in Metadata and if it gets changed then ther was likely invalid or corrupted mem
const uintptr_t MAGIC_NUMBER = 0xDEADBEEF; // found DEADBEEF in slides

// minimum unique pointer for sz 0 allocations
static void* zero_size_unique_ptr = (void*)0x1;

// store all of the allocated memory pointers in the map
// bool value associated with each allocation to determine weather double free occurs
std::map<void*, bool> pointerMap;
std::unordered_map<std::string, size_t> heavy_hitters_map;

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
     // if size is 0, return a unique pointer
    if (sz == 0) {
        return zero_size_unique_ptr;
    }

    // allocate mem for the Metadata and user-requested size
    size_t total_size = sizeof(Metadata) + sz + 400; //+ sizeof(unsigned int*) + sizeof(unsigned int*);
    Metadata* metadata = (Metadata*) base_malloc(total_size);

    if (!metadata) {
        // handle failure in mem allocation
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return nullptr;
    }   

    // sz is a size_t value, SIZE_MAX is the max possible value of a size_t
    if (sz > total_size) {
        // handle failure in mem allocation for allocs that are too large
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return nullptr;
    }

    // metadata is mapped to false when malloced
    pointerMap[(void*)((uintptr_t)metadata + sizeof(Metadata) + 200)] = false;

    // initial allocation_size
    metadata->allocation_size = sz;
    metadata->file = file;
    metadata->line = line;
    metadata->magic_number = MAGIC_NUMBER;

    // update statistics
    global_stats.nactive++;
    global_stats.ntotal++;
    global_stats.active_size += sz;
    global_stats.total_size += sz;
    
    // set canaries
    uintptr_t canary = 0xDEADBEEF;
    uintptr_t *underflow_canary = (uintptr_t *)((uintptr_t)metadata + sizeof(Metadata));
    uintptr_t *overflow_canary = (uintptr_t *)((uintptr_t)underflow_canary + 200 + metadata->allocation_size);
    for(int i = 0; i < 25; i++) {
        underflow_canary[i] = canary;
    }
    for(int i = 0; i < 25; i++) {
        overflow_canary[i] = canary;
    }
    // cout << "metadata: " << (uintptr_t)metadata << ", underflow: " << (uintptr_t)underflow_canary << ", overflow: " << (uintptr_t)overflow_canary << endl;

    // update heap boundaries to ensure mem is within bounds -> for leak detection/tracking
    uintptr_t alloc_address = (uintptr_t)(metadata + 1) + 200;  // handle on the actual mem address (after Metadata)
    if (global_stats.heap_min == 0 || alloc_address < global_stats.heap_min) {
        global_stats.heap_min = alloc_address; 
    }

    if (alloc_address > global_stats.heap_max) {
        global_stats.heap_max = alloc_address + sz;
    }

    heavy_hitters_size += sz;
    std::string format = std::string(file) + std::string(":") + std::string(std::to_string(line));
    heavy_hitters_map[format] += sz;

    // return ptr to the mem that comes after the Metadata
    return (void*)(alloc_address); // moves the pointer past the Metadata block to the actual memory returned to the user.
}

// helper for free to assist with advanced reporting
void check_pointer_in_other_allocations(void* ptr) {
    // traverse over allocations in map
    for (const auto& entry : pointerMap) {
        if (!entry.second) { // if pointer has not been freed
            Metadata* metadata = (Metadata*)((char*)entry.first - sizeof(Metadata) - 200);
            uintptr_t start_address = (uintptr_t)entry.first;
            uintptr_t end_address = start_address + metadata->allocation_size;

            // check if the invalid pointer falls within block
            if ((uintptr_t)ptr >= start_address && (uintptr_t)ptr < end_address) {
                fprintf(stderr, "  %s:%ld: %p is %lu bytes inside a %lu byte region allocated here\n",
                        metadata->file, metadata->line, ptr,
                        (uintptr_t)ptr - start_address, metadata->allocation_size);
                abort();
            }
        }
    }
}

/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    if (!ptr || ptr == zero_size_unique_ptr) {
        return;
    }

    // check if pointer is within heap boundaries
    uintptr_t ptr_address = (uintptr_t) ptr;
    if (ptr_address < global_stats.heap_min || ptr_address > global_stats.heap_max) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap", file, line, ptr);
        invalid_free_found = true;
        abort(); 
    }

    // access the metadata from the allocated memory
    Metadata* metadata = (Metadata*)(ptr_address - 200 - sizeof(Metadata));

    // check if magic number has been corrupted or if pointer is in map
    if (pointerMap.find(ptr) == pointerMap.end() || metadata->magic_number != MAGIC_NUMBER) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        check_pointer_in_other_allocations(ptr);
        invalid_free_found = true;
        abort();
    }

    // check if the pointer has already been freed
    if (pointerMap[ptr] == true) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
        abort();
    }

    // check canaries
    bool wildwrite = false;
    uintptr_t canary = 0xDEADBEEF;
    uintptr_t *underflow_canary = (uintptr_t *)((uintptr_t)metadata + sizeof(Metadata));
    uintptr_t *overflow_canary = (uintptr_t *)((uintptr_t)underflow_canary + 200 + metadata->allocation_size);
    for(int i = 0; i < 25; i++) {
        if(underflow_canary[i] != canary) {
            wildwrite = true;
            break;
        }
    }
    for(int i = 0; i < 25; i++) {
        if(overflow_canary[i] != canary) {
            wildwrite = true;
            break;
        }
    }
    if(wildwrite) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
        abort();
    }

    // update statistics
    global_stats.nactive--;
    global_stats.active_size -= metadata->allocation_size;

    base_free(metadata);
    pointerMap[ptr] = true;
}


/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {

    // check for overflow before multiplication for total size
    if (nmemb != 0 && sz > SIZE_MAX / nmemb) {
        // handle failure in memory allocation for allocations that are too large
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return nullptr;
    }

    // total size that needs to be allocated
    size_t total_size = nmemb*sz;

    void* ptr = dmalloc_malloc(total_size, file, line);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

/// dmalloc_get_statistics(stats)
/// Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    //memset(stats, 255, sizeof(dmalloc_statistics));
    if (stats){
        *stats = global_stats; // copy the global stats to provided structure
    }
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);
    // make sure stats are not printed if there is an invalid free
    if (invalid_free_found){
        return;
    }
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.
// //! LEAK CHECK: test???.cc:16: allocated object ??ptr?? with size ??size??

void dmalloc_print_leak_report() {

     // iterate over the map to find active allocations
    for (const auto& entry : pointerMap) {
        if (!entry.second) { // if pointer associated bool value is still marked as not false
            Metadata* metadata = (Metadata*)((char*)entry.first - sizeof(Metadata) - 200); // point to metadata
            fprintf(stdout, "LEAK CHECK: %s:%ld: allocated object %p with size %lu\n", 
                metadata->file, metadata->line, entry.first, metadata->allocation_size);
        }
    }
}

// prints the top 5 heaviest hitters
void dmalloc_print_heavy_hitter_report() {
    const int TOP_N = 5;  // number of top heaviest hitters to report
    std::vector<std::pair<std::string, size_t>> heavy_hitters_pairs;
    double percentage;

    for (int i = 0; i < TOP_N; i++) {
        // find the largest allocation (by size) in heavy_hitters_map
        auto max = heavy_hitters_map.begin();
        for (auto it = heavy_hitters_map.begin(); it != heavy_hitters_map.end(); it++) {
            if (it->second > max->second) {
                max = it;  // update max if a larger element is found
            }
        }

        // reached end
        if (max == heavy_hitters_map.end()) {
            break;
        } else {
            // push the found largest allocation into heavy_hitters_pairs vector
            heavy_hitters_pairs.push_back(*max);
            // erase current max from map so next largest can be found
            heavy_hitters_map.erase(max);
        }
    }

    for (const auto& max_pair : heavy_hitters_pairs) {
        // extract file:line pair (first element) and the size in bytes (second element) from pair
        const std::string& file_line_pair = max_pair.first;
        size_t byte_size = max_pair.second;
        percentage = ((double)(byte_size) / (double)heavy_hitters_size) * 100;  // calculate %
        printf("HEAVY HITTER: %s: %ld bytes (~%.1f%%)\n", file_line_pair.c_str(), byte_size, percentage);
    }
}
