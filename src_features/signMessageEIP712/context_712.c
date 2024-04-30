#ifdef HAVE_EIP712_FULL_SUPPORT

#include <string.h>
#include <stdint.h>
#include "context_712.h"
#include "mem.h"
#include "mem_utils.h"
#include "sol_typenames.h"
#include "path.h"
#include "field_hash.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "apdu_constants.h"  // APDU response codes
#include "shared_context.h"  // reset_app_context
#include "common_ui.h"       // ui_idle

e_struct_init struct_state = NOT_INITIALIZED;
s_eip712_context *eip712_context = NULL;

/**
 * Initialize the EIP712 context
 *
 * @return a boolean indicating if the initialization was successful or not
 */
uint32_t eip712_context_init(void) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;
    // init global variables
    mem_init();

    if ((eip712_context = MEM_ALLOC_AND_ALIGN_TYPE(*eip712_context)) == NULL) {
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }

    sw = sol_typenames_init();
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }

    sw = path_init();
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }

    sw = field_hash_init();
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }

    sw = ui_712_init();
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }

    sw = typed_data_init();  // this needs to be initialized last !
    if (sw != APDU_RESPONSE_OK) {
        return sw;
    }

    // Since they are optional, they might not be provided by the JSON data
    explicit_bzero(eip712_context->contract_addr, sizeof(eip712_context->contract_addr));
    eip712_context->chain_id = 0;

    struct_state = NOT_INITIALIZED;

    return APDU_RESPONSE_OK;
}

/**
 * De-initialize the EIP712 context
 */
void eip712_context_deinit(void) {
    typed_data_deinit();
    path_deinit();
    field_hash_deinit();
    ui_712_deinit();
    mem_reset();
    eip712_context = NULL;
    reset_app_context();
}

#endif
