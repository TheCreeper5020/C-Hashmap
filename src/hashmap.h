#ifndef HASHMAP_H
#define HASHMAP_H

#include <stddef.h>

typedef struct map_t map_t;

/*
    Hashes a `key` of given `size`.
    Suitable for passing in as the `hash_key` argument for `map_create`
*/
size_t map_hash(void *key, size_t size);

/*
    Allocates memory for and creates a map.
    `initial_capacity` specifies how many buckets the map should have initially.
        If set to zero, then the implementation chooses a default size.
    `get_key_length` is a function for computing the key length of a key, for hashing and comparison
    `key_equal` is a function for determining if two keys compare equal, used so that the hashmap has no duplicates.
*/
map_t *map_create(size_t initial_capacity, 
    size_t (*hash_key)(void*, size_t),
    size_t (*get_key_length)(void*),
    bool (*key_equal)(const void*, const void*, size_t));

/*
    This function is analogous to `map_create`, except instead of specifying a function to compute the length of keys,
    it accepts the key size upfront. This should be used when the key size doesn't differ between keys (e.g. if keys
    are integers, but not if they are strings)
*/
map_t *map_create_static(size_t initial_capacity,
    size_t (*hash_key)(void*, size_t),
    size_t key_length,
    bool (*key_equal)(const void*, const void*, size_t));

/*
    This function frees a map.
    If you do not call this, you will have a memory leak!
*/
void map_free(map_t *map);

#endif