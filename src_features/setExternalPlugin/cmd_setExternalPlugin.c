#include "shared_context.h"
#include "apdu_constants.h"
#include "public_keys.h"
#include "eth_plugin_interface.h"
#include "eth_plugin_internal.h"
#include "plugin_utils.h"
#include "common_ui.h"
#include "os_io_seproxyhal.h"

uint32_t handleSetExternalPlugin(const uint8_t *workBuffer, uint8_t dataLength) {
    PRINTF("Handling set Plugin\n");
    uint8_t hash[INT256_LENGTH];
    cx_ecfp_public_key_t tokenKey;
    uint8_t pluginNameLength = *workBuffer;
    PRINTF("plugin Name Length: %d\n", pluginNameLength);
    const size_t payload_size = 1 + pluginNameLength + ADDRESS_LENGTH + SELECTOR_SIZE;

    if (dataLength <= payload_size) {
        PRINTF("data too small: expected at least %d got %d\n", payload_size, dataLength);
        return APDU_RESPONSE_INVALID_DATA;
    }

    if (pluginNameLength + 1 > sizeof(dataContext.tokenContext.pluginName)) {
        PRINTF("name length too big: expected max %d, got %d\n",
               sizeof(dataContext.tokenContext.pluginName),
               pluginNameLength + 1);
        return APDU_RESPONSE_INVALID_DATA;
    }

    // check Ledger's signature over the payload
    cx_hash_sha256(workBuffer, payload_size, hash, sizeof(hash));
    CX_ASSERT(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1,
                                               LEDGER_SIGNATURE_PUBLIC_KEY,
                                               sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                               &tokenKey));
    if (!cx_ecdsa_verify_no_throw(&tokenKey,
                                  hash,
                                  sizeof(hash),
                                  workBuffer + payload_size,
                                  dataLength - payload_size)) {
#ifndef HAVE_BYPASS_SIGNATURES
        PRINTF("Invalid plugin signature %.*H\n",
               dataLength - payload_size,
               workBuffer + payload_size);
        return APDU_RESPONSE_INVALID_DATA;
#endif
    }

    // move on to the rest of the payload parsing
    workBuffer++;
    memmove(dataContext.tokenContext.pluginName, workBuffer, pluginNameLength);
    dataContext.tokenContext.pluginName[pluginNameLength] = '\0';
    workBuffer += pluginNameLength;

    PRINTF("Check external plugin %s\n", dataContext.tokenContext.pluginName);

    // Check if the plugin is present on the device
    uint32_t params[2];
    params[0] = (uint32_t) dataContext.tokenContext.pluginName;
    params[1] = ETH_PLUGIN_CHECK_PRESENCE;
    BEGIN_TRY {
        TRY {
            os_lib_call(params);
        }
        CATCH_OTHER(e) {
            PRINTF("%s external plugin is not present\n", dataContext.tokenContext.pluginName);
            memset(dataContext.tokenContext.pluginName,
                   0,
                   sizeof(dataContext.tokenContext.pluginName));
            return APDU_RESPONSE_PLUGIN_NOT_INSTALLED;
        }
        FINALLY {
        }
    }
    END_TRY;

    PRINTF("Plugin found\n");

    memmove(dataContext.tokenContext.contractAddress, workBuffer, ADDRESS_LENGTH);
    workBuffer += ADDRESS_LENGTH;
    memmove(dataContext.tokenContext.methodSelector, workBuffer, SELECTOR_SIZE);

    pluginType = EXTERNAL;

    return APDU_RESPONSE_OK;
}
