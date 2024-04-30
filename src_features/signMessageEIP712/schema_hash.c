#ifdef HAVE_EIP712_FULL_SUPPORT

#include "schema_hash.h"
#include "hash_bytes.h"
#include "typed_data.h"
#include "format_hash_field_type.h"
#include "context_712.h"
#include "apdu_constants.h"

// the SDK does not define a SHA-224 type, define it here so it's easier
// to understand in the code
typedef cx_sha256_t cx_sha224_t;

/**
 * Compute the schema hash
 *
 * The schema hash is the value of the root field "types" in the JSON data,
 * stripped of all its spaces and newlines. This function reconstructs the JSON syntax
 * from the stored typed data.
 *
 * @return whether the schema hash was successful or not
 */
uint32_t compute_schema_hash(void) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;
    const void *struct_ptr;
    uint8_t structs_count;
    const void *field_ptr;
    uint8_t fields_count;
    const char *name;
    uint8_t name_length;
    cx_sha224_t hash_ctx;
    cx_err_t error = CX_INTERNAL_ERROR;

    cx_sha224_init(&hash_ctx);

    struct_ptr = get_structs_array(&structs_count);
    hash_byte('{', (cx_hash_t *) &hash_ctx);
    while (structs_count-- > 0) {
        name = get_struct_name(struct_ptr, &name_length);
        hash_byte('"', (cx_hash_t *) &hash_ctx);
        hash_nbytes((uint8_t *) name, name_length, (cx_hash_t *) &hash_ctx);
        hash_nbytes((uint8_t *) "\":[", 3, (cx_hash_t *) &hash_ctx);
        field_ptr = get_struct_fields_array(struct_ptr, &fields_count);
        while (fields_count-- > 0) {
            hash_nbytes((uint8_t *) "{\"name\":\"", 9, (cx_hash_t *) &hash_ctx);
            name = get_struct_field_keyname(field_ptr, &name_length);
            if (!name) {
                return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            }
            hash_nbytes((uint8_t *) name, name_length, (cx_hash_t *) &hash_ctx);
            hash_nbytes((uint8_t *) "\",\"type\":\"", 10, (cx_hash_t *) &hash_ctx);
            sw = format_hash_field_type(field_ptr, (cx_hash_t *) &hash_ctx);
            if (sw != APDU_RESPONSE_OK) {
                return sw;
            }
            hash_nbytes((uint8_t *) "\"}", 2, (cx_hash_t *) &hash_ctx);
            if (fields_count > 0) {
                hash_byte(',', (cx_hash_t *) &hash_ctx);
            }
            field_ptr = get_next_struct_field(field_ptr);
            if (!field_ptr) {
                return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            }
        }
        hash_byte(']', (cx_hash_t *) &hash_ctx);
        if (structs_count > 0) {
            hash_byte(',', (cx_hash_t *) &hash_ctx);
        }
        struct_ptr = get_next_struct(struct_ptr);
        if (!struct_ptr) {
            return APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        }
    }
    hash_byte('}', (cx_hash_t *) &hash_ctx);

    // copy hash into context struct
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &hash_ctx,
                              CX_LAST,
                              NULL,
                              0,
                              eip712_context->schema_hash,
                              sizeof(eip712_context->schema_hash)));
    error = APDU_RESPONSE_OK;
end:
    return error;
}

#endif  // HAVE_EIP712_FULL_SUPPORT
