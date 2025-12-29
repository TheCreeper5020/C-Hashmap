#include "hashmap.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define RET_SUCCESS(retn) do { error_code = MAP_ERROR_OK; return retn; } while (0)
#define RET_PTR_ERROR(code) do { error_code = code; return NULL; } while (0)
#define RET_INT_ERROR(code) do { error_code = code; return -1; } while (0)

static const size_t load_max = 75;

static const size_t default_initial_capacity = 64;
static const size_t default_pair_count = 4;

typedef struct bucket_t {
    void **data;        // nth key at 2n, nth value at 2n+1
    size_t *hash_cache; // nth key's hash at n
    size_t pair_count, pair_max;
} bucket_t;

typedef struct map_fp_table_t {
    map_hash_function hash;
    map_key_length_function length;
} map_fp_table_t;

typedef struct map_t {
    bucket_t *buckets;
    size_t bucket_count;
    size_t static_key_size; // if zero, call function_table.length()
    size_t element_count;
    map_fp_table_t function_table;
} map_t;

static _Thread_local int error_code = MAP_ERROR_OK;

int map_last_error() {
    return error_code;
}

char *map_str_error(int error_code) {
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
        default:
            return "Unknown error code";
    }
}

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

size_t map_strlen(const void *key) {
    return strlen(key);
}

map_t *make_map(size_t initial_capacity, map_hash_function hash) {
    if (!hash) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
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
    result->element_count = 0;

    RET_SUCCESS(result);
}

map_t *map_create(size_t initial_capacity, map_hash_function hash, map_key_length_function get_key_length) {
    if (!get_key_length) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
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

static bool bucket_contains(const map_t *map, size_t location, const void *key, size_t key_hash) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket->pair_count == 0) {
        return false;
    }

    size_t key_len = get_length(map, key);

    for (size_t i = 0; i < bucket->pair_count; i++) {
        if (key_hash == bucket->hash_cache[i]
            && key_len == get_length(map, bucket->data[i * 2])
            && !memcmp(bucket->data[i * 2], key, key_len)) {
            return true;
        }
    }
    return false;
}

static void *bucket_get(map_t *map, size_t location, void *key, size_t key_hash) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket->pair_count == 0) {
        RET_PTR_ERROR(MAP_ERROR_NOTFOUND);
    }

    size_t key_len = get_length(map, key);
    
    for (size_t i = 0; i < bucket->pair_count; i++) {
        if (key_hash == bucket->hash_cache[i]
            && key_len == get_length(map, bucket->data[i * 2])
            && !memcmp(bucket->data[i * 2], key, key_len)) {
            RET_SUCCESS(bucket->data[i * 2 + 1]);
        }
    }

    RET_PTR_ERROR(MAP_ERROR_NOTFOUND);
}

static int bucket_direct_insert(bucket_t *bucket, void *key, size_t key_hash, void *value) {
    if (bucket->pair_max == 0) {
        bucket->data = malloc(default_pair_count * 2 * sizeof(void*));
        bucket->hash_cache = malloc(default_pair_count * sizeof(size_t));
        if (!bucket->data || !bucket->hash_cache) {
            free(bucket->data);
            free(bucket->hash_cache);
            RET_INT_ERROR(MAP_ERROR_NOALLOC);
        }
        bucket->pair_max = default_pair_count;
    }
    if (bucket->pair_count >= bucket->pair_max) {
        size_t new_max = bucket->pair_max * 2;
        while (bucket->pair_count >= new_max) {
            new_max *= 2;
        }

        void **new_data = malloc(new_max * 2 * sizeof(void*));
        size_t *new_hash_cache = malloc(new_max * sizeof(size_t));
        if (!new_data || !new_hash_cache) {
            free(new_data);
            free(new_hash_cache);
            RET_INT_ERROR(MAP_ERROR_NOALLOC);
        }

        memcpy(new_data, bucket->data, bucket->pair_count * 2 * sizeof(void*));
        memcpy(new_hash_cache, bucket->hash_cache, bucket->pair_count * sizeof(size_t));
        free(bucket->data);
        free(bucket->hash_cache);
        bucket->data = new_data;
        bucket->hash_cache = new_hash_cache;
        bucket->pair_max = new_max;
    }
    bucket->data[2 * bucket->pair_count] = key;
    bucket->data[2 * bucket->pair_count + 1] = value;
    bucket->hash_cache[bucket->pair_count] = key_hash;

    bucket->pair_count++;
    RET_SUCCESS(0);
}

static int bucket_insert(map_t *map, size_t location, void *key, size_t hash, void *value) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket_contains(map, location, key, hash)) {
        RET_INT_ERROR(MAP_ERROR_DUPE);
    }
    return bucket_direct_insert(bucket, key, hash, value);
}

static int bucket_remove(map_t *map, size_t location, void *key, size_t key_hash) {
    bucket_t *bucket = &map->buckets[location];
    if (bucket->pair_count == 0) {
        RET_INT_ERROR(MAP_ERROR_NOTFOUND);
    }

    size_t key_len = get_length(map, key);

    for (size_t i = 0; i < bucket->pair_count; i++) {
        if (key_hash == bucket->hash_cache[i]
            && key_len == get_length(map, bucket->data[i * 2]) 
            && !memcmp(key, bucket->data[i * 2], key_len)) {
            memmove(&bucket->data[i * 2], &bucket->data[i * 2 + 2], 2 * sizeof(void*) * (bucket->pair_count - i - 1));
            memmove(&bucket->hash_cache[i], &bucket->hash_cache[i + 1], sizeof(size_t) * (bucket->pair_count - i - 1));
            bucket->pair_count--;
            map->element_count--;
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
        free(buckets[i].data);
        free(buckets[i].hash_cache);
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
            void *key = bucket->data[2 * j];
            void *value = bucket->data[2 * j + 1];
            size_t hash = bucket->hash_cache[j];
            if (bucket_direct_insert(&new_buckets[hash % new_capacity], key, hash, value) < 0) {
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
        /* We ignore the return value from this, since if it fails we can just try again next time */
        map_rehash(map, new_capacity);
    }

    size_t key_hash = map->function_table.hash(key, get_length(map, key));
    size_t bucket_index = key_hash % map->bucket_count;

    int bucket_insert_retval = bucket_insert(map, bucket_index, key, key_hash, value);
    if (bucket_insert_retval < 0) {
        return -1;
    }
    map->element_count++;
    RET_SUCCESS(0);
}

bool map_contains(map_t *map, void *key) {
    if (!map) {
        RET_INT_ERROR(MAP_ERROR_INVALID);
    }
    size_t hash = map->function_table.hash(key, get_length(map, key));
    size_t bucket_index = hash % map->bucket_count;
    return bucket_contains(map, bucket_index, key, hash);
}

void *map_get(map_t *map, void *key) {
    if (!map) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
    size_t hash = map->function_table.hash(key, get_length(map, key));
    size_t bucket_index = hash % map->bucket_count;
    return bucket_get(map, bucket_index, key, hash);
}

int map_remove(map_t *map, void *key) {
    if (!map) {
        RET_INT_ERROR(MAP_ERROR_INVALID);
    }
    size_t hash = map->function_table.hash(key, get_length(map, key));
    size_t bucket_index = hash % map->bucket_count;
    return bucket_remove(map, bucket_index, key, hash);
}

void map_free(map_t *map) {
    if (!map) {
        return;
    }
    free_buckets(map->buckets, map->bucket_count);
    free(map);
}
