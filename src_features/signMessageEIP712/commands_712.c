#ifdef HAVE_EIP712_FULL_SUPPORT

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "commands_712.h"
#include "apdu_constants.h"  // APDU response codes
#include "context_712.h"
#include "field_hash.h"
#include "path.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "schema_hash.h"
#include "filtering.h"
#include "common_712.h"
#include "common_ui.h"  // ui_idle

/**
 * Send the response to the previous APDU command
 *
 * In case of an error it uses the global variable to retrieve the error code and resets
 * the app context
 *
 * @param[in] result whether the command was successful
 */
static void handle_eip712_context(uint32_t result) {
    if (result != APDU_RESPONSE_OK) {
        eip712_context_deinit();
        ui_idle();
    }
}

/**
 * Process the EIP712 struct definition command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
uint32_t handle_eip712_struct_def(const uint8_t *const apdu_buf) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;

    if (eip712_context == NULL) {
        sw = eip712_context_init();
    }

    if (struct_state == DEFINED) {
        // TODO: Check appropriate error code...
        sw = APDU_RESPONSE_PLUGIN_ERROR;
    }

    if (sw == APDU_RESPONSE_OK) {
        switch (apdu_buf[OFFSET_P2]) {
            case P2_DEF_NAME:
                sw = set_struct_name(apdu_buf[OFFSET_LC], &apdu_buf[OFFSET_CDATA]);
                break;
            case P2_DEF_FIELD:
                sw = set_struct_field(apdu_buf[OFFSET_LC], &apdu_buf[OFFSET_CDATA]);
                break;
            default:
                PRINTF("Unknown P2 0x%x for APDU 0x%x\n",
                       apdu_buf[OFFSET_P2],
                       apdu_buf[OFFSET_INS]);
                sw = APDU_RESPONSE_INVALID_P1_P2;
        }
    }
    handle_eip712_context(sw);
    return sw;
}

/**
 * Process the EIP712 struct implementation command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
uint32_t handle_eip712_struct_impl(const uint8_t *const apdu_buf) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;
    // TODO: Check how to NOT reply APDU!!!
    bool reply_apdu = true;

    if (eip712_context == NULL) {
        sw = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    } else {
        switch (apdu_buf[OFFSET_P2]) {
            case P2_IMPL_NAME:
                // set root type
                sw = path_set_root((char *) &apdu_buf[OFFSET_CDATA], apdu_buf[OFFSET_LC]);
                if (sw == APDU_RESPONSE_OK) {
                    if (N_storage.verbose_eip712) {
                        ui_712_review_struct(path_get_root());
                        reply_apdu = false;
                    }
                    ui_712_field_flags_reset();
                }
                break;
            case P2_IMPL_FIELD:
                if ((sw = field_hash(&apdu_buf[OFFSET_CDATA],
                                     apdu_buf[OFFSET_LC],
                                     apdu_buf[OFFSET_P1] != P1_COMPLETE))) {
                    reply_apdu = false;
                }
                break;
            case P2_IMPL_ARRAY:
                sw = path_new_array_depth(&apdu_buf[OFFSET_CDATA], apdu_buf[OFFSET_LC]);
                break;
            default:
                PRINTF("Unknown P2 0x%x for APDU 0x%x\n",
                       apdu_buf[OFFSET_P2],
                       apdu_buf[OFFSET_INS]);
                sw = APDU_RESPONSE_INVALID_P1_P2;
        }
    }
    if (reply_apdu) {
        handle_eip712_context(sw);
    }
    return sw;
}

/**
 * Process the EIP712 filtering command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
uint32_t handle_eip712_filtering(const uint8_t *const apdu_buf) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;
    // TODO: Check how to NOT reply APDU!!!
    bool reply_apdu = true;
    e_filtering_type type;

    if (eip712_context == NULL) {
        sw = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    } else {
        switch (apdu_buf[OFFSET_P2]) {
            case P2_FILT_ACTIVATE:
                if (!N_storage.verbose_eip712) {
                    ui_712_set_filtering_mode(EIP712_FILTERING_FULL);
                    sw = compute_schema_hash();
                }
                break;
            case P2_FILT_MESSAGE_INFO:
            case P2_FILT_SHOW_FIELD:
                type = (apdu_buf[OFFSET_P2] == P2_FILT_MESSAGE_INFO)
                           ? FILTERING_PROVIDE_MESSAGE_INFO
                           : FILTERING_SHOW_FIELD;
                if (ui_712_get_filtering_mode() == EIP712_FILTERING_FULL) {
                    sw = provide_filtering_info(&apdu_buf[OFFSET_CDATA], apdu_buf[OFFSET_LC], type);
                    if ((apdu_buf[OFFSET_P2] == P2_FILT_MESSAGE_INFO) && (sw == APDU_RESPONSE_OK)) {
                        reply_apdu = false;
                    }
                }
                break;
            default:
                PRINTF("Unknown P2 0x%x for APDU 0x%x\n",
                       apdu_buf[OFFSET_P2],
                       apdu_buf[OFFSET_INS]);
                sw = APDU_RESPONSE_INVALID_P1_P2;
        }
    }
    if (reply_apdu) {
        handle_eip712_context(sw);
    }
    return sw;
}

/**
 * Process the EIP712 sign command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
uint32_t handle_eip712_sign(const uint8_t *const apdu_buf) {
    uint32_t sw = APDU_RESPONSE_UNKNOWN;
    uint8_t length = apdu_buf[OFFSET_LC];

    if (eip712_context == NULL) {
        sw = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }
    // if the final hashes are still zero or if there are some unimplemented fields
    else if (allzeroes(tmpCtx.messageSigningContext712.domainHash,
                       sizeof(tmpCtx.messageSigningContext712.domainHash)) ||
             allzeroes(tmpCtx.messageSigningContext712.messageHash,
                       sizeof(tmpCtx.messageSigningContext712.messageHash)) ||
             (path_get_field() != NULL)) {
        sw = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    } else if ((ui_712_get_filtering_mode() == EIP712_FILTERING_FULL) &&
               (ui_712_remaining_filters() != 0)) {
        PRINTF("%d EIP712 filters are missing\n", ui_712_remaining_filters());
        sw = APDU_RESPONSE_REF_DATA_NOT_FOUND;
    } else if (parseBip32(&apdu_buf[OFFSET_CDATA], &length, &tmpCtx.messageSigningContext.bip32) !=
               NULL) {
        if (!N_storage.verbose_eip712 && (ui_712_get_filtering_mode() == EIP712_FILTERING_BASIC)) {
            ui_712_message_hash();
        }
        sw = ui_712_end_sign();
    }
    handle_eip712_context(sw);
    return sw;
}

#endif  // HAVE_EIP712_FULL_SUPPORT
