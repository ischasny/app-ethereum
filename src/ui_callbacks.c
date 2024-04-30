#include "shared_context.h"
#include "feature_getPublicKey.h"
#include "common_ui.h"
#include "apdu_constants.h"

unsigned int ui_cb_ok(uint32_t tx) {
    U2BE_ENCODE(G_io_apdu_buffer, tx, APDU_RESPONSE_OK);
    tx += 2;
    reset_app_context();
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0;  // do not redraw the widget
}

unsigned int ui_cb_cancel() {
    io_seproxyhal_send_status(APDU_RESPONSE_CONDITION_NOT_SATISFIED, true);
    return 0;  // do not redraw the widget
}
