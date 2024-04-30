#include "os_io_seproxyhal.h"
#include "apdu_constants.h"
#include "crypto_helpers.h"
#include "common_ui.h"
#include "ledger_assert.h"

unsigned int io_seproxyhal_touch_signMessage_ok(void) {
    unsigned int info = 0;
    if (bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                            tmpCtx.messageSigningContext.bip32.path,
                                            tmpCtx.messageSigningContext.bip32.length,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            tmpCtx.messageSigningContext.hash,
                                            sizeof(tmpCtx.messageSigningContext.hash),
                                            G_io_apdu_buffer + 1,
                                            G_io_apdu_buffer + 1 + 32,
                                            &info) != CX_OK) {
        LEDGER_ASSERT(false, "bip32_derive_ecdsa_sign_rs_hash_256");
    }
    G_io_apdu_buffer[0] = 27;
    if (info & CX_ECCINFO_PARITY_ODD) {
        G_io_apdu_buffer[0]++;
    }
    if (info & CX_ECCINFO_xGTn) {
        G_io_apdu_buffer[0] += 2;
    }
    return ui_cb_ok(65);
}

unsigned int io_seproxyhal_touch_signMessage_cancel(void) {
    return ui_cb_cancel();
}
