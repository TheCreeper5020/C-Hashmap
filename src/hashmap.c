#include "hashmap.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define RET_SUCCESS(retn) do { error_code = MAP_ERROR_OK; return retn; } while (0)
#define RET_PTR_ERROR(code) do { error_code = code; return NULL; } while (0)
#define RET_INT_ERROR(code) do { error_code = code; return -1; } while (0)

static const size_t load_max = 75;

static const size_t default_initial_capacity = 64;
static const size_t default_pair_count = 4;

typedef struct map_key_t {
    void *bytes;
    uint64_t hash;
    size_t len;
} map_key_t;

typedef struct kvp_t {
    map_key_t key;
    void *value;
} kvp_t;

typedef struct bucket_t {
    kvp_t *pairs;
    size_t pair_count, pair_max;
} bucket_t;

typedef struct map_fp_table_t {
    map_hash_function hash;
    map_key_length_function length;
} map_fp_table_t;

struct map_t {
    bucket_t        *buckets;
    size_t          bucket_count;
    size_t          static_key_size; // if zero, call function_table.length()
    size_t          element_count;
    map_fp_table_t  function_table;
};

struct map_iterator_t {
    map_t *map;
    size_t current_bucket, current_pair;
};

static _Thread_local int error_code = MAP_ERROR_OK;

int map_last_error() {
    return error_code;
}

const char *map_str_error(int error_code) {
    switch (error_code) {
        case MAP_ERROR_OK:
            return "Ok";
        case MAP_ERROR_INVALID:
            return "Invalid argument";
        case MAP_ERROR_NOALLOC:
            return "Allocation failed";
        case MAP_ERROR_NOTFOUND:
            return "Element not found within map";
        case MAP_ERROR_DUPE:
            return "Attempt to insert a duplicate element";
        case MAP_ERROR_OUT_OF_BOUNDS:
            return "Attempt to access out of bounds memory region";
        default:
            return "Unknown error code";
    }
}

/*
    Implementation of FNV-1a for either 32-bit or 64-bit size_t
*/
uint64_t map_hash(const void *key, size_t size) {
    static const uint64_t FNV_offset_basis = 14695981039346656037ull;
    static const uint64_t FNV_prime = 1099511628211ull;

    const char *bytes = (const char*)(key);
    uint64_t hash = FNV_offset_basis;

    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= FNV_prime;
    }

    return hash;
}

size_t map_strlen(const void *key) {
    return strlen((const char*)(key));
}

static map_t *make_map(size_t initial_capacity, map_hash_function hash) {
    map_t *result = malloc(sizeof(map_t));
    if (!result) {
        RET_PTR_ERROR(MAP_ERROR_NOALLOC);
    }
    if (initial_capacity == 0) {
        initial_capacity = default_initial_capacity;
    }
    result->buckets = calloc(initial_capacity, sizeof(bucket_t));
    if (!result->buckets) {
        free(result);
        RET_PTR_ERROR(MAP_ERROR_NOALLOC);
    }
    result->bucket_count = initial_capacity;

    result->function_table.hash = hash ? hash : map_hash;
    result->function_table.length = NULL;
    result->static_key_size = 0;
    result->element_count = 0;

    RET_SUCCESS(result);
}

map_t *map_create(size_t initial_capacity, map_hash_function hash, map_key_length_function get_key_length) {
    map_t *map = make_map(initial_capacity, hash);
    if (!map) {
        return NULL;
    }
    map->static_key_size = 0;
    map->function_table.length = get_key_length ? get_key_length : map_strlen;
    return map;
}

map_t *map_create_static(size_t initial_capacity, map_hash_function hash, size_t key_length) {
    if (key_length == 0) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
    map_t *map = make_map(initial_capacity, hash);
    if (!map) {
        return NULL;
    }
    map->static_key_size = key_length;
    return map;
}

static size_t get_length(const map_t *map, const void *key) {
    if (map->static_key_size == 0) {
        return map->function_table.length(key);
    }
    return map->static_key_size;
}

static bool bucket_contains(const map_t *map, uint64_t location, map_key_t *key) {
    bucket_t *bucket = &map->buckets[location];

    if (bucket->pair_count == 0) {
        return false;
    }

    for (size_t i = 0; i < bucket->pair_count; i++) {
        kvp_t *pair = &bucket->pairs[i];
        if (key->hash == pair->key.hash
            && key->len == pair->key.len
            && !memcmp(pair->key.bytes, key->bytes, key->len)) {
            return true;
        }
    }
    return false;
}

static void *bucket_get(map_t *map, uint64_t location, map_key_t *key) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket->pair_count == 0) {
        RET_PTR_ERROR(MAP_ERROR_NOTFOUND);
    }

    for (size_t i = 0; i < bucket->pair_count; i++) {
        kvp_t *pair = &bucket->pairs[i];
        if (key->hash == pair->key.hash
            && key->len == pair->key.len
            && !memcmp(pair->key.bytes, key->bytes, key->len)) {
            RET_SUCCESS(pair->value);
        }
    }

    RET_PTR_ERROR(MAP_ERROR_NOTFOUND);
}

static int bucket_direct_insert(bucket_t *bucket, map_key_t *key, void *value) {
    if (bucket->pair_max == 0) {
        bucket->pairs = malloc(default_pair_count * sizeof(kvp_t));
        if (!bucket->pairs) {
            RET_INT_ERROR(MAP_ERROR_NOALLOC);
        }
        bucket->pair_max = default_pair_count;
    }
    if (bucket->pair_count >= bucket->pair_max) {
        size_t new_max = bucket->pair_max * 2;
        while (bucket->pair_count >= new_max) {
            new_max *= 2;
        }

        kvp_t *new_pairs = realloc(bucket->pairs, new_max * sizeof(kvp_t));
        if (!new_pairs) {
            RET_INT_ERROR(MAP_ERROR_NOALLOC);
        }

        bucket->pairs = new_pairs;
        bucket->pair_max = new_max;
    }

    bucket->pairs[bucket->pair_count].key = *key;
    bucket->pairs[bucket->pair_count].value = value;

    bucket->pair_count++;
    RET_SUCCESS(0);
}

static int bucket_insert(map_t *map, uint64_t location, map_key_t *key, void *value) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket_contains(map, location, key)) {
        RET_INT_ERROR(MAP_ERROR_DUPE);
    }
    return bucket_direct_insert(bucket, key, value);
}

static int bucket_remove(map_t *map, size_t location, map_key_t *key) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket->pair_count == 0) {
        RET_INT_ERROR(MAP_ERROR_NOTFOUND);
    }

    for (size_t i = 0; i < bucket->pair_count; i++) {
        kvp_t *pair = &bucket->pairs[i];
        if (key->hash == pair->key.hash 
            && key->len == pair->key.len 
            && !memcmp(pair->key.bytes, key->bytes, key->len)) {
            memmove(&bucket->pairs[i], &bucket->pairs[i + 1], sizeof(kvp_t) * (bucket->pair_count - i - 1));
            bucket->pair_count--;
            RET_SUCCESS(0);
        }
    }
    RET_INT_ERROR(MAP_ERROR_NOTFOUND);
}

static void free_buckets(bucket_t *buckets, size_t bucket_count) {
    if (!buckets) {
        return;
    }
    for (size_t i = 0; i < bucket_count; i++) {
        free(buckets[i].pairs);
    }
    free(buckets);
}

static size_t load_factor(size_t element_count, size_t bucket_count) {
    return (element_count * 100) / bucket_count;
}

static int map_rehash(map_t *map, size_t new_capacity) {
    bucket_t *new_buckets = calloc(new_capacity, sizeof(bucket_t));
    if (!new_buckets) {
        RET_INT_ERROR(MAP_ERROR_NOALLOC);
    }
    for (size_t i = 0; i < map->bucket_count; i++) {
        bucket_t *bucket = &map->buckets[i];
        for (size_t j = 0; j < bucket->pair_count; j++) {
            uint64_t insert_at = bucket->pairs[j].key.hash % new_capacity; 
            if (bucket_direct_insert(&new_buckets[insert_at], &bucket->pairs[j].key, bucket->pairs[j].value) < 0) {
                free_buckets(new_buckets, new_capacity);
                return -1; 
            }
        }
    }

    free_buckets(map->buckets, map->bucket_count);
    map->buckets = new_buckets;
    map->bucket_count = new_capacity;
    RET_SUCCESS(0);
}

int map_insert(map_t *map, void *key, void *value) {
    if (!map) {
        RET_INT_ERROR(MAP_ERROR_INVALID);
    }
    if (load_factor(map->element_count, map->bucket_count) >= load_max) {
        size_t new_capacity = map->bucket_count * 2;
        while (load_factor(map->element_count, new_capacity) >= load_max) {
            new_capacity *= 2;
        }
        if (map_rehash(map, new_capacity) < 0) {
            return -1;
        }
    }

    size_t key_length = get_length(map, key);
    uint64_t key_hash = map->function_table.hash(key, key_length);
    uint64_t bucket_index = key_hash % map->bucket_count;

    map_key_t key_to_insert = {
        .bytes = key,
        .len = key_length,
        .hash = key_hash,
    };

    int bucket_insert_retval = bucket_insert(map, bucket_index, &key_to_insert, value);
    if (bucket_insert_retval < 0) {
        return -1;
    }
    map->element_count++;
    RET_SUCCESS(0);
}

bool map_contains(map_t *map, void *key) {
    if (!map) {
        error_code = MAP_ERROR_INVALID;
        return false;
    }

    size_t length = get_length(map, key);
    uint64_t hash = map->function_table.hash(key, length);
    uint64_t bucket_index = hash % map->bucket_count;

    map_key_t key_to_check = {
        .bytes = key,
        .len = length,
        .hash = hash,
    };

    return bucket_contains(map, bucket_index, &key_to_check);
}

void *map_get(map_t *map, void *key) {
    if (!map) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }

    size_t length = get_length(map, key);
    uint64_t hash = map->function_table.hash(key, length);
    uint64_t bucket_index = hash % map->bucket_count;

    map_key_t key_to_check = {
        .bytes = key,
        .len = length,
        .hash = hash,
    };

    return bucket_get(map, bucket_index, &key_to_check);
}

int map_remove(map_t *map, void *key) {
    if (!map) {
        RET_INT_ERROR(MAP_ERROR_INVALID);
    }

    size_t length = get_length(map, key);
    uint64_t hash = map->function_table.hash(key, length);
    uint64_t bucket_index = hash % map->bucket_count;

    map_key_t key_to_check = {
        .bytes = key,
        .len = length,
        .hash = hash,
    };

    if (bucket_remove(map, bucket_index, &key_to_check) < 0) {
        return -1;
    }
    map->element_count--;
    RET_SUCCESS(0);
}

void map_free(map_t *map) {
    if (!map) {
        return;
    }
    free_buckets(map->buckets, map->bucket_count);
    free(map);
}

static map_iterator_t *iterator_alloc(map_t *map) {
    if (!map) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
    map_iterator_t *result = malloc(sizeof(map_iterator_t));
    if (!result) {
        RET_PTR_ERROR(MAP_ERROR_NOALLOC);
    }
    result->map = map;
    return result;
}

static size_t find_next_nonempty_bucket(map_t *map, size_t start_pos) {
    for (size_t i = start_pos; i < map->bucket_count; i++) {
        if (map->buckets[i].pair_count > 0) {
            return i;
        }
    }
    return map->bucket_count;
}

map_iterator_t *map_begin(map_t *map) {
    map_iterator_t *result = iterator_alloc(map);
    if (!result) {
        return NULL;
    }

    result->current_bucket = find_next_nonempty_bucket(map, 0);
    result->current_pair = 0;

    RET_SUCCESS(result);
}

map_iterator_t *map_end(map_t *map) {
    map_iterator_t *result = iterator_alloc(map);
    if (!result) {
        return NULL;
    }

    result->current_bucket = map->bucket_count;
    result->current_pair = 0;

    return result;
}

int map_next(map_iterator_t *iterator) {
    if (iterator->current_bucket >= iterator->map->bucket_count) {
        RET_INT_ERROR(MAP_ERROR_OUT_OF_BOUNDS);
    }
    iterator->current_pair++;
    if (iterator->current_pair >= iterator->map->buckets[iterator->current_bucket].pair_count) {
        iterator->current_bucket = find_next_nonempty_bucket(iterator->map, iterator->current_bucket + 1);
        iterator->current_pair = 0;
    }
    RET_SUCCESS(0);
}

int map_get_pair(map_iterator_t *iterator, void **key, void **value) {
    if (!key || !value) {
        RET_INT_ERROR(MAP_ERROR_INVALID);
    }

    if (iterator->current_bucket >= iterator->map->bucket_count) {
        RET_INT_ERROR(MAP_ERROR_OUT_OF_BOUNDS);
    }

    kvp_t *pair = &iterator->map->buckets[iterator->current_bucket].pairs[iterator->current_pair];
    *key = pair->key.bytes;
    *value = pair->value;

    RET_SUCCESS(0);
}

bool iterator_equal(map_iterator_t *a, map_iterator_t *b) {
    if (!a || !b) {
        return false;
    }
    return !memcmp(a, b, sizeof(map_iterator_t));
}

void map_iterator_free(map_iterator_t *iterator) {
    free(iterator);
}