#include <nbgl_page.h>
#include "shared_context.h"
#include "ui_callbacks.h"
#include "ui_nbgl.h"

static void reviewReject(void) {
  io_seproxyhal_touch_address_cancel(NULL);
  ui_idle();
}

static void confirmTransation(void) {
  io_seproxyhal_touch_address_ok(NULL);
  ui_idle();
}

static void reviewChoice(bool confirm) {
  if (confirm) {
    confirmTransation();
  } else {
    reviewReject();
  }
}

static void buildScreen(void) {
  snprintf(strings.tmp.tmp, 100, "0x%.*H", 48, tmpCtx.publicKeyContext.publicKey.W);
  nbgl_useCaseChoice(
    "Export ETH2 public key?",
    "Allow the Ethereum app\nto export your ETH2\npublic key.",
    "Allow",
    "Don't allow",
    reviewChoice
  );
}

void ui_display_public_eth2(void) {
  buildScreen();
}