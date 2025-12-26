#include "hashmap.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static const size_t default_initial_capacity = 64;

typedef struct bucket_t {
    void **data; // nth key at 2n, nth value at 2n+1
    size_t pair_count, pair_max;
} bucket_t;

typedef struct map_t {
    bucket_t *buckets;
    size_t bucket_count;
    size_t (*hash_function)(const void*, size_t);
    bool static_key_size;
    union {
        size_t bytes;                           // if static_size is TRUE
        size_t (*compute_size)(const void*);    // if static_size is FALSE
    } key_size;
    bool (*key_equal)(const void*, const void*, size_t);
} map_t;

/*
    Implementation of FNV-1a for either 32-bit or 64-bit size_t
*/
size_t map_hash(const void *key, size_t size) {
    static const size_t FNV_offset_basis = sizeof(size_t) == 8 ? 14695981039346656037ull : 2166136261ul;
    static const size_t FNV_prime = sizeof(size_t) == 8 ? 1099511628211ull : 16777619ul;

    char *bytes = (char*)(key);
    size_t hash = FNV_offset_basis;

    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= FNV_prime;
    }

    return hash;
}

bool map_key_equal(const void *key_a, const void *key_b, size_t size) {
    return !memcmp(key_a, key_b, size);
}

static map_t *make_map(size_t initial_capacity,
    size_t (*hash_key)(const void*, size_t),
    bool (*key_equal)(const void*, const void*, size_t)) {
    map_t *result = malloc(sizeof(map_t));
    if (!result) {
        return NULL;
    }
    if (initial_capacity == 0) {
        initial_capacity = default_initial_capacity;
    }
    result->buckets = calloc(initial_capacity, sizeof(bucket_t));
    if (!result->buckets) {
        free(result);
        return NULL;
    }
    result->bucket_count = initial_capacity;

    result->hash_function = hash_key ? hash_key : map_hash;
    result->key_equal = key_equal ? key_equal : map_key_equal;

    return result;
}

map_t *map_create(size_t initial_capacity, 
    size_t (*hash_key)(const void*, size_t),
    size_t (*get_key_length)(const void*),
    bool (*key_equal)(const void*, const void*, size_t)) {
    map_t *map = make_map(initial_capacity, hash_key, key_equal);
    if (!map) {
        return NULL;
    }
    map->static_key_size = false;
    map->key_size.compute_size = get_key_length ? get_key_length : (size_t (*)(const void*))(strlen);
    return map;
}

map_t *map_create_static(size_t initial_capacity,
    size_t (*hash_key)(const void*, size_t),
    size_t key_length,
    bool (*key_equal)(const void*, const void*, size_t)) {
    map_t *map = make_map(initial_capacity, hash_key, key_equal);
    if (!map) {
        return NULL;
    }
    map->static_key_size = true;
    map->key_size.bytes = key_length;
    return map;
}

static void free_buckets(bucket_t *buckets, size_t bucket_count) {
    if (!buckets) {
        return;
    }
    for (size_t i = 0; i < bucket_count; i++) {
        free(buckets[i].data);
    }
    free(buckets);
}

void map_free(map_t *map) {
    if (!map) {
        return;
    }
    free_buckets(map->buckets, map->bucket_count);
    free(map);
}