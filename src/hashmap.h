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
typedef size_t      (*map_length_function)(const void*);

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
    dynamic key/value size overload of map_create, see map_create for more details
*/
map_t *map_create_dd(size_t initial_capacity, map_hash_function hash, map_length_function get_key_length, map_length_function get_value_length);

/*
    dynamic key size overload of map_create, with value size fixed, see map_create for more details
*/
map_t *map_create_ds(size_t initial_capacity, map_hash_function hash, map_length_function get_key_length, size_t value_length);

/*
    dynamic value size overload of map_create, with key size fixed, see map_create for more details
*/
map_t *map_create_sd(size_t initial_capacity, map_hash_function hash, size_t key_length, map_length_function get_value_length);

/*
    static key/value size overload of map_create, see map_create for more details
*/
map_t *map_create_ss(size_t initial_capacity, map_hash_function hash, size_t key_length, size_t value_length);

/*
    Create a map.
    `initial_capacity` specifies the initial capacity of the map, or 0 to let the library
    choose a size.
    `hash_function` specifies a hash function to use, or NULL to use map_hash
    `key_length` is either a nonzero size_t specifying the size of a key, or a pointer
    to a function which accepts a `const void*` and returns the size of a key. If a NULL
    pointer is specified, map_strlen is used.
    `value_length` specifies the size of a value in the same way key_length does. 
    Note that you might need to cast key_length or value_length to size_t if passing
    an integer directly
*/
#define map_create(initial_capacity, hash_function, key_length, value_length) _Generic((key_length),\
    size_t: _Generic((value_length),\
        size_t: map_create_ss,\
        map_length_function: map_create_sd,\
        void*: map_create_sd\
    ),\
    map_length_function: _Generic((value_length),\
        size_t: map_create_ds,\
        map_length_function: map_create_dd,\
        void*: map_create_dd\
    ),\
    void*: _Generic((value_length),\
        size_t: map_create_ds,\
        map_length_function: map_create_dd,\
        void*: map_create_dd\
    )\
)((initial_capacity), (hash_function), (key_length), (value_length))

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
    Clear all elements from map, and set its size to zero.
    This also frees some memory.
*/
void map_clear(map_t *map);

/*
    Tests if map_size would return 0 (the map has no keys associated with any values)
*/
bool map_empty(map_t *map);

/*
    Tests if two maps are equivalent (i.e. they contain the same keys and the same keys are
    associated with the same values)
*/
bool map_equal(map_t *a, map_t *b);

/*
    Obtains the size of the map.
*/
size_t map_size(map_t *map);

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
    Obtain the key-value pair that `iterator` currently points to.
    `key` should point to a variable to recieve the key.
    `value` should point to a variable to recieve the value.
*/
int map_get_pair(map_iterator_t *iterator, void **key, void **value);

/*
    Determine if two map_iterator_t compare equal.
*/
bool map_iterator_equal(map_iterator_t *a, map_iterator_t *b);

/*
    Free any memory associated with `iterator`
*/
void map_iterator_free(map_iterator_t *iterator);

#endif