#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
    Error handling for the hashmap library
*/

#define MAP_ERROR_OK            0
#define MAP_ERROR_NOALLOC       1
#define MAP_ERROR_INVALID       2
#define MAP_ERROR_DUPE          3
#define MAP_ERROR_NOTFOUND      4
#define MAP_ERROR_OUT_OF_BOUNDS 5

int map_last_error();
const char *map_str_error(int error_code);

typedef struct map_t map_t;
typedef struct map_iterator_t map_iterator_t;

typedef uint64_t    (*map_hash_function)(const void*, size_t);
typedef size_t      (*map_key_length_function)(const void*);

/*
    Hashes a `key` of given `size`.
    Suitable for passing in as the `hash_key` argument for `map_create`
*/
uint64_t map_hash(const void *key, size_t size);

/*
    Wrapper around strlen accepting const void* instead of const char*
    The key is expected to be terminated by a NULL byte.
*/
size_t map_strlen(const void *key);

/*
    Allocates memory for and creates a map.
    `initial_capacity` specifies how many buckets the map should have initially.
        If set to zero, then the implementation chooses a default size.
    `hash_key` is a function for hashing a key. If set to NULL, it will be as if you passed `map_hash`
    `get_key_length` is a function for computing the key length of a key, for hashing and comparison
        If set to NULL, it will be as if you passed `map_strlen`.
*/
map_t *map_create(size_t initial_capacity, map_hash_function hash, map_key_length_function get_key_length);

/*
    This function is analogous to `map_create`, except instead of specifying a function to compute the length of keys,
    it accepts the key size upfront. This should be used when the key size doesn't differ between keys (e.g. if keys
    are integers, but not if they are strings)
*/
map_t *map_create_static(size_t initial_capacity, map_hash_function hash, size_t key_length);

/*
    Inserts `key` into `map` and associates it with `value`.
    Returns 0 on success or -1 on failure.
    NOTE: this does not copy key or value into the hashmap. If the memory that key or value points to
    is deallocated, the map will have a dangling pointer. Ensure that memory in the map outlives the map.
*/
int map_insert(map_t *map, void *key, void *value);

/*
    returns true if `key` occurs in `map`, otherwise false
*/
bool map_contains(map_t *map, void *key);

/*
    Retrieve the value associated with `key` from map.
    Returns NULL if no such value was found.
*/
void *map_get(map_t *map, void *key);

/*
    Remove `key` and its associated value from `map`.
    Returns -1 if `key` does not exist in `map`.
*/
int map_remove(map_t *map, void *key);

/*
    This function frees a map.
    If you do not call this, you will have a memory leak!
*/
void map_free(map_t *map);

/*
    Create an iterator over `map` at the start
*/
map_iterator_t *map_begin(map_t *map);

/*
    Create an iterator over `map` at the end
*/
map_iterator_t *map_end(map_t *map);

/*
    Move `iterator` forward one unit in the map. Returns -1 if attempting to go past map_end()
*/
int map_next(map_iterator_t *iterator);

/*
    Move `iterator` backward one unit in the map. Returns -1 if attempting to go past map_begin()
*/
int map_prev(map_iterator_t *iterator);

/*
    Free any memory associated with `iterator`
*/
void map_iterator_free(map_iterator_t *iterator);

#endif