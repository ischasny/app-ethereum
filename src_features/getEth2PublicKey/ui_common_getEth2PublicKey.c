#ifdef HAVE_ETH2

#include "shared_context.h"
#include "feature_getEth2PublicKey.h"
#include "common_ui.h"
#include "apdu_constants.h"

unsigned int io_seproxyhal_touch_eth2_address_ok(__attribute__((unused)) const bagl_element_t *e) {
    uint32_t tx = set_result_get_eth2_publicKey();
    return ui_cb_ok(tx);
}

#endif
