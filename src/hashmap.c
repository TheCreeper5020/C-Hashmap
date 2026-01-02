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

typedef struct map_data_t {
    void *bytes;
    size_t len;
} map_data_t;

typedef struct map_key_t {
    map_data_t data;
    uint64_t hash;
} map_key_t;

typedef struct kvp_t {
    map_key_t key;
    map_data_t value;
    bool copied;
} kvp_t;

typedef struct bucket_t {
    kvp_t *pairs;
    size_t pair_count, pair_max;
} bucket_t;

typedef struct map_fp_table_t {
    map_hash_function hash;
    map_length_function key_length;
    map_length_function value_length;
} map_fp_table_t;

struct map_t {
    bucket_t        *buckets;
    size_t          bucket_count;
    size_t          static_key_size;
    size_t          static_value_size;
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
    return strlen((const char*)(key)) + 1;
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
    result->function_table.key_length = NULL;
    result->function_table.value_length = NULL;
    result->static_key_size = 0;
    result->static_value_size = 0;
    result->element_count = 0;

    RET_SUCCESS(result);
}

map_t *map_create_dd(size_t initial_capacity, map_hash_function hash, map_length_function get_key_length, map_length_function get_value_length) {
    map_t *map = make_map(initial_capacity, hash);
    if (!map) {
        return NULL;
    }
    map->function_table.key_length = get_key_length ? get_key_length : map_strlen;
    map->function_table.value_length = get_value_length ? get_value_length : map_strlen;
    return map;
}

map_t *map_create_ds(size_t initial_capacity, map_hash_function hash, map_length_function get_key_length, size_t value_length) {
    if (value_length == 0) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
    map_t *map = make_map(initial_capacity, hash);
    if (!map) {
        return NULL;
    }
    map->function_table.key_length = get_key_length ? get_key_length : map_strlen;
    map->static_value_size = value_length;
    return map;
}

map_t *map_create_sd(size_t initial_capacity, map_hash_function hash, size_t key_length, map_length_function get_value_length) {
    if (key_length == 0) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
    map_t *map = make_map(initial_capacity, hash);
    if (!map) {
        return NULL;
    }
    map->static_key_size = key_length;
    map->function_table.value_length = get_value_length ? get_value_length : map_strlen;
    return map;
}

map_t *map_create_ss(size_t initial_capacity, map_hash_function hash, size_t key_length, size_t value_length) {
    if (key_length == 0 || value_length == 0) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }
    map_t *map = make_map(initial_capacity, hash);
    if (!map) {
        return NULL;
    }
    map->static_key_size = key_length;
    map->static_value_size = value_length;
    return map;
}

static size_t get_key_length(const map_t *map, const void *key) {
    if (map->static_key_size == 0) {
        return map->function_table.key_length(key);
    }
    return map->static_key_size;
}

static size_t get_value_length(const map_t *map, const void *value) {
    if (map->static_value_size == 0) {
        return map->function_table.value_length(value);
    }
    return map->static_value_size;
}

static bool key_equal(const map_key_t *a, const map_key_t *b) {
    return a->hash == b->hash 
        && a->data.len == b->data.len
        && !memcmp(a->data.bytes, b->data.bytes, a->data.len);
}

static bool value_equal(const map_data_t *a, const map_data_t *b) {
    return a->len == b->len && !memcmp(a->bytes, b->bytes, a->len);
}

static map_data_t *bucket_get(bucket_t *bucket, map_key_t *key) {
    for (size_t i = 0; i < bucket->pair_count; i++) {
        kvp_t *pair = &bucket->pairs[i];
        if (key_equal(key, &pair->key)) {
            RET_SUCCESS(&pair->value);
        }
    }

    RET_PTR_ERROR(MAP_ERROR_NOTFOUND);
}

static bool bucket_contains(bucket_t *bucket, map_key_t *key) {
    for (size_t i = 0; i < bucket->pair_count; i++) {
        kvp_t *pair = &bucket->pairs[i];
        if (key_equal(key, &pair->key)) {
            return true;     
        }
    }

    return false;
}

static int bucket_resize(bucket_t *bucket, size_t new_max) {
    kvp_t *new_pairs = realloc(bucket->pairs, new_max * sizeof(kvp_t));
    if (!new_pairs) {
        RET_INT_ERROR(MAP_ERROR_NOALLOC);
    }

    bucket->pairs = new_pairs;
    bucket->pair_max = new_max;
    RET_SUCCESS(0);
}

// ensure the bucket has at least cap_at_least slots for elements
static int bucket_ensure(bucket_t *bucket, size_t cap_at_least) {
    if (cap_at_least == 0) {
        RET_SUCCESS(0);
    }
    if (bucket->pair_max == 0) {
        bucket->pairs = malloc(default_pair_count * sizeof(kvp_t));
        if (!bucket->pairs) {
            RET_INT_ERROR(MAP_ERROR_NOALLOC);
        }
        bucket->pair_max = default_pair_count;
    }
    if (cap_at_least > bucket->pair_max) {
        size_t new_max = bucket->pair_max * 2;
        while (cap_at_least >= new_max) {
            new_max *= 2;
        }
        if (bucket_resize(bucket, new_max) < 0) {
            return -1;
        }
    }
    RET_SUCCESS(0);
}

static int bucket_insert(bucket_t *bucket, map_key_t *key, map_data_t *value, bool copy) {
    if (bucket_contains(bucket, key)) {
        RET_INT_ERROR(MAP_ERROR_DUPE);
    }

    if (bucket_ensure(bucket, bucket->pair_count + 1) < 0) {
        return -1;
    }

    bucket->pairs[bucket->pair_count].key = *key;
    bucket->pairs[bucket->pair_count].value = *value;
    bucket->pairs[bucket->pair_count].copied = copy;

    bucket->pair_count++;
    RET_SUCCESS(0);
}

static int bucket_remove(bucket_t *bucket, map_key_t *key) {
    if (bucket->pair_count == 0) {
        RET_INT_ERROR(MAP_ERROR_NOTFOUND);
    }

    for (size_t i = 0; i < bucket->pair_count; i++) {
        kvp_t *pair = &bucket->pairs[i];
        if (key_equal(key, &pair->key)) {
            if (pair->copied) {
                free(pair->key.data.bytes);
                free(pair->value.bytes);
            }
            memmove(&bucket->pairs[i], &bucket->pairs[i + 1], sizeof(kvp_t) * (bucket->pair_count - i - 1));
            bucket->pair_count--;
            RET_SUCCESS(0);
        }
    }
    RET_INT_ERROR(MAP_ERROR_NOTFOUND);
}

static void free_bucket(bucket_t *bucket) {
    for (size_t i = 0; i < bucket->pair_count; i++) {
        if (bucket->pairs[i].copied) {
            free(bucket->pairs[i].key.data.bytes);
            free(bucket->pairs[i].value.bytes);
        }
    }
    free(bucket->pairs);
}

static void free_buckets(bucket_t *buckets, size_t bucket_count) {
    if (!buckets) {
        return;
    }
    for (size_t i = 0; i < bucket_count; i++) {
        free_bucket(&buckets[i]);
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
            kvp_t *pair = &bucket->pairs[j];

            map_key_t *key = &pair->key;
            map_data_t *value = &pair->value;

            uint64_t insert_at = key->hash % new_capacity; 

            if (bucket_insert(&new_buckets[insert_at], key, value, pair->copied) < 0) {
                /* We cannot use free_buckets because it would leave the map in an inconsistent
                state. */
                for (size_t i = 0; i < new_capacity; i++) {
                    free(new_buckets[i].pairs);
                }
                free(new_buckets);
                return -1; 
            }
        }
    }

    for (size_t i = 0; i < map->bucket_count; i++) {
        free(map->buckets[i].pairs);
    }
    free(map->buckets);

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

    size_t key_length = get_key_length(map, key);
    uint64_t key_hash = map->function_table.hash(key, key_length);
    uint64_t bucket_index = key_hash % map->bucket_count;

    size_t value_length = get_value_length(map, value);

    map_key_t key_to_insert = {
        .data = {
            .bytes = key, .len = key_length
        },
        .hash = key_hash,
    };

    map_data_t value_to_insert = {
        .bytes = value, .len = value_length,
    };

    if (bucket_insert(&map->buckets[bucket_index], &key_to_insert, &value_to_insert, false) < 0) {
        return -1;
    }
    map->element_count++;
    RET_SUCCESS(0);
}

int map_insert_copy(map_t *map, void *key, void *value) {
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
    size_t key_length = get_key_length(map, key);
    uint64_t key_hash = map->function_table.hash(key, key_length);
    uint64_t bucket_index = key_hash % map->bucket_count;

    size_t value_length = get_value_length(map, value);

    map_key_t key_to_insert = {
        .data = {
            .bytes = malloc(key_length),
            .len = key_length,
        },
        .hash = key_hash,
    };
    if (!key_to_insert.data.bytes) {
        RET_INT_ERROR(MAP_ERROR_NOALLOC);
    }
    memcpy(key_to_insert.data.bytes, key, key_length);

    map_data_t value_to_insert = {
        .bytes = malloc(value_length),
        .len = value_length
    };
    if (!value_to_insert.bytes) {
        free(key_to_insert.data.bytes);
        RET_INT_ERROR(MAP_ERROR_NOALLOC);
    }
    memcpy(value_to_insert.bytes, value, value_length);

    if (bucket_insert(&map->buckets[bucket_index], &key_to_insert, &value_to_insert, true) < 0) {
        free(key_to_insert.data.bytes);
        free(value_to_insert.bytes);
        return -1;
    }
    map->element_count++;
    RET_SUCCESS(0);
}

bool map_contains(map_t *map, void *key) {
    if (!map) {
        return false;
    }

    size_t length = get_key_length(map, key);
    uint64_t hash = map->function_table.hash(key, length);
    uint64_t bucket_index = hash % map->bucket_count;

    map_key_t key_to_check = {
        .data = {
            .bytes = key, .len = length
        },
        .hash = hash,
    };

    return bucket_contains(&map->buckets[bucket_index], &key_to_check);
}

void *map_get(map_t *map, void *key) {
    if (!map) {
        RET_PTR_ERROR(MAP_ERROR_INVALID);
    }

    size_t length = get_key_length(map, key);
    uint64_t hash = map->function_table.hash(key, length);
    uint64_t bucket_index = hash % map->bucket_count;

    map_key_t key_to_check = {
        .data = {
            .bytes = key, .len = length
        },
        .hash = hash,
    };

    map_data_t *data = bucket_get(&map->buckets[bucket_index], &key_to_check);
    if (!data) {
        return NULL;
    }
    return data->bytes;
}

int map_remove(map_t *map, void *key) {
    if (!map) {
        RET_INT_ERROR(MAP_ERROR_INVALID);
    }

    size_t length = get_key_length(map, key);
    uint64_t hash = map->function_table.hash(key, length);
    uint64_t bucket_index = hash % map->bucket_count;

    map_key_t key_to_check = {
        .data = {
            .bytes = key, .len = length
        },
        .hash = hash,
    };

    if (bucket_remove(&map->buckets[bucket_index], &key_to_check) < 0) {
        return -1;
    }
    map->element_count--;
    RET_SUCCESS(0);
}

void map_clear(map_t *map) {
    if (!map) {
        return;
    }

    map->element_count = 0;
    for (size_t i = 0; i < map->bucket_count; i++) {
        free_bucket(&map->buckets[i]);
        map->buckets[i].pairs = NULL;
        map->buckets[i].pair_count = map->buckets[i].pair_max = 0;
    }
}

bool map_empty(map_t *map) {
    if (!map) {
        return true;
    }
    return map->element_count == 0;
}

bool map_equal(map_t *a, map_t *b) {
    if (a->element_count != b->element_count) {
        return false;
    }

    for (size_t i = 0; i < a->bucket_count; i++) {
        bucket_t *bucket = &a->buckets[i];
        for (size_t j = 0; j < bucket->pair_count; j++) {
            kvp_t *pair = &bucket->pairs[j];

            size_t b_location = pair->key.hash % b->bucket_count;

            map_data_t *value = bucket_get(&b->buckets[b_location], &pair->key);

            if (!value || !value_equal(&pair->value, value)) {
                return false;
            }
        }
    }
    return true;
}

size_t map_size(map_t *map) {
    return map->element_count;
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
    *key = pair->key.data.bytes;
    *value = pair->value.bytes;

    RET_SUCCESS(0);
}

bool map_iterator_equal(map_iterator_t *a, map_iterator_t *b) {
    if (!a || !b) {
        return false;
    }
    return a->current_bucket == b->current_bucket && a->current_pair == b->current_pair && a->map == b->map;
}

bool map_at_end(map_iterator_t *iterator) {
    if (!iterator) {
        return true;
    }
    return iterator->current_bucket >= iterator->map->bucket_count; 
}

void map_iterator_free(map_iterator_t *iterator) {
    free(iterator);
}

int map_foreach(map_t *map, map_foreach_function function) {
    int retval = 0;
    for (size_t i = 0; i < map->bucket_count; i++) {
        bucket_t *bucket = &map->buckets[i];
        for (size_t j = 0; j < bucket->pair_count; j++) {
            kvp_t *pair = &bucket->pairs[j];
            retval = function(pair->key.data.bytes, pair->value.bytes);
            if (retval == 1) {
                return retval;
            }
        }
    }
    return retval;
}