#ifdef HAVE_EIP712_FULL_SUPPORT

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "mem.h"
#include "mem_utils.h"
#include "type_hash.h"
#include "shared_context.h"
#include "format_hash_field_type.h"
#include "hash_bytes.h"
#include "apdu_constants.h"  // APDU response codes
#include "typed_data.h"

/**
 * Encode & hash the given structure field
 *
 * @param[in] field_ptr pointer to the struct field
 * @return \ref true it finished correctly, \ref false if it didn't (memory allocation)
 */
static uint32_t encode_and_hash_field(const void *const field_ptr) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;
    const char *name;
    uint8_t length;

    sw = format_hash_field_type(field_ptr, (cx_hash_t *) &global_sha3);
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }
    // space between field type name and field name
    hash_byte(' ', (cx_hash_t *) &global_sha3);

    // field name
    name = get_struct_field_keyname(field_ptr, &length);
    if (!name) {
        return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }
    hash_nbytes((uint8_t *) name, length, (cx_hash_t *) &global_sha3);
    return APDU_RESPONSE_OK;
}

/**
 * Encode & hash the a given structure type
 *
 * @param[in] struct_ptr pointer to the structure we want the typestring of
 * @param[in] str_length length of the formatted string in memory
 * @return error code
 */
static uint32_t encode_and_hash_type(const void *const struct_ptr) {
    const char *struct_name;
    uint8_t struct_name_length;
    const uint8_t *field_ptr;
    uint8_t fields_count;
    uint32_t sw = APDU_RESPONSE_UNKNOWN;

    // struct name
    struct_name = get_struct_name(struct_ptr, &struct_name_length);
    if (!struct_name) {
        return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }
    hash_nbytes((uint8_t *) struct_name, struct_name_length, (cx_hash_t *) &global_sha3);

    // opening struct parentheses
    hash_byte('(', (cx_hash_t *) &global_sha3);

    field_ptr = get_struct_fields_array(struct_ptr, &fields_count);
    for (uint8_t idx = 0; idx < fields_count; ++idx) {
        // comma separating struct fields
        if (idx > 0) {
            hash_byte(',', (cx_hash_t *) &global_sha3);
        }

        sw = encode_and_hash_field(field_ptr);
        if (sw != APDU_RESPONSE_OK) {
            return sw;
        }

        field_ptr = get_next_struct_field(field_ptr);
        if (!field_ptr) {
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        }
    }
    // closing struct parentheses
    hash_byte(')', (cx_hash_t *) &global_sha3);

    return APDU_RESPONSE_OK;
}

/**
 * Sort the given structs based by alphabetical order
 *
 * @param[in] deps_count count of how many struct dependencies pointers
 * @param[in,out] deps pointer to the first dependency pointer
 */
static uint32_t sort_dependencies(uint8_t deps_count, const void **deps) {
    bool changed;
    const void *tmp_ptr;
    const char *name1, *name2;
    uint8_t namelen1, namelen2;
    int str_cmp_result;

    do {
        changed = false;
        for (size_t idx = 0; (idx + 1) < deps_count; ++idx) {
            name1 = get_struct_name(*(deps + idx), &namelen1);
            if (!name1) {
                return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            }
            name2 = get_struct_name(*(deps + idx + 1), &namelen2);
            if (!name2) {
                return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            }

            str_cmp_result = strncmp(name1, name2, MIN(namelen1, namelen2));
            if ((str_cmp_result > 0) || ((str_cmp_result == 0) && (namelen1 > namelen2))) {
                tmp_ptr = *(deps + idx);
                *(deps + idx) = *(deps + idx + 1);
                *(deps + idx + 1) = tmp_ptr;

                changed = true;
            }
        }
    } while (changed);
    return APDU_RESPONSE_OK;
}

/**
 * Find all the dependencies from a given structure
 *
 * @param[out] deps_count count of how many struct dependency pointers
 * @param[in] first_dep pointer to the first dependency pointer
 * @param[in] struct_ptr pointer to the struct we are getting the dependencies of
 * @return pointer to the first found dependency, \ref NULL otherwise
 */
static const void **get_struct_dependencies(uint8_t *const deps_count,
                                            const void **first_dep,
                                            const void *const struct_ptr) {
    uint8_t fields_count;
    const void *field_ptr;
    const char *arg_structname;
    uint8_t arg_structname_length;
    const void *arg_struct_ptr;
    size_t dep_idx;
    const void **new_dep;

    field_ptr = get_struct_fields_array(struct_ptr, &fields_count);
    for (uint8_t idx = 0; idx < fields_count; ++idx) {
        if (struct_field_type(field_ptr) == TYPE_CUSTOM) {
            // get struct name
            arg_structname = get_struct_field_typename(field_ptr, &arg_structname_length);
            // from its name, get the pointer to its definition
            arg_struct_ptr = get_structn(arg_structname, arg_structname_length);

            // check if it is not already present in the dependencies array
            for (dep_idx = 0; dep_idx < *deps_count; ++dep_idx) {
                // it's a match!
                if (*(first_dep + dep_idx) == arg_struct_ptr) {
                    break;
                }
            }
            // if it's not present in the array, add it and recurse into it
            if (dep_idx == *deps_count) {
                *deps_count += 1;
                if ((new_dep = MEM_ALLOC_AND_ALIGN_TYPE(void *)) == NULL) {
                    return NULL;
                }
                if (*deps_count == 1) {
                    first_dep = new_dep;
                }
                *new_dep = arg_struct_ptr;
                // TODO: Move away from recursive calls
                get_struct_dependencies(deps_count, first_dep, arg_struct_ptr);
            }
        }
        field_ptr = get_next_struct_field(field_ptr);
    }
    return first_dep;
}

/**
 * Encode the structure's type and hash it
 *
 * @param[in] struct_name name of the given struct
 * @param[in] struct_name_length length of the name of the given struct
 * @param[out] hash_buf buffer containing the resulting type_hash
 * @return whether the type_hash was successful or not
 */
uint32_t type_hash(const char *const struct_name,
                   const uint8_t struct_name_length,
                   uint8_t *hash_buf) {
    const void *const struct_ptr = get_structn(struct_name, struct_name_length);
    uint8_t deps_count = 0;
    const void **deps;
    void *mem_loc_bak = mem_alloc(0);
    cx_err_t error = CX_INTERNAL_ERROR;
    uint32_t sw = APDU_RESPONSE_UNKNOWN;

    if (!struct_ptr) {
        return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }
    CX_CHECK(cx_keccak_init_no_throw(&global_sha3, 256));
    deps = get_struct_dependencies(&deps_count, NULL, struct_ptr);
    if ((deps_count > 0) && (deps == NULL)) {
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }
    sw = sort_dependencies(deps_count, deps);
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }
    sw = encode_and_hash_type(struct_ptr);
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }
    // loop over each struct and generate string
    for (int idx = 0; idx < deps_count; ++idx) {
        sw = encode_and_hash_type(*deps);
        if (sw != APDU_RESPONSE_OK) {
            return sw;
        }
        deps += 1;
    }
    mem_dealloc(mem_alloc(0) - mem_loc_bak);

    // copy hash into memory
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                              CX_LAST,
                              NULL,
                              0,
                              hash_buf,
                              KECCAK256_HASH_BYTESIZE));
    error = APDU_RESPONSE_OK;
end:
    return error;
}

#endif  // HAVE_EIP712_FULL_SUPPORT
