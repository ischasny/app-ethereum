#include "common_ui.h"
#include "ui_nbgl.h"
#include "common_712.h"

static nbgl_layoutTagValue_t tlv[2];

static char domain_hash[70];
static char message_hash[70];

static void reviewReject(void) {
  ui_712_approve_cb(NULL);
  ui_idle();
}

static void confirmTransation(void) {
  ui_712_reject_cb(NULL);
  ui_idle();
}

static void reviewChoice(bool confirm) {
  if (confirm) {
    confirmTransation();
  } else {
    reviewReject();
  }
}

static bool displayTransactionPage(uint8_t page, nbgl_pageContent_t *content) {
  snprintf(domain_hash, 70, "0x%.*H", 32, tmpCtx.messageSigningContext712.domainHash);
  snprintf(message_hash, 70, "0x%.*H", 32, tmpCtx.messageSigningContext712.messageHash);

  if (page == 0) {
    tlv[0].item = "Domain hash";
    tlv[0].value = domain_hash;
    tlv[1].item = "Message hash";
    tlv[1].value = message_hash;

    content->type = TAG_VALUE_LIST;
    content->tagValueList.nbPairs = 2;
    content->tagValueList.pairs = (nbgl_layoutTagValue_t *)tlv;
  }
  else if (page == 1) {
    content->type = INFO_LONG_PRESS,
    content->infoLongPress.icon = &C_badge_transaction_56;
    content->infoLongPress.text = "Sign typed message";
    content->infoLongPress.longPressText = "Hold to approuve";
  }
  else {
    return false;
  }
  // valid page so return true
  return true;
}
static void reviewContinue(void) {
  nbgl_useCaseRegularReview(0, 2, "Reject", NULL, displayTransactionPage, reviewChoice);
}


static void buildFirstPage(void) {
  nbgl_useCaseReviewStart(&C_badge_transaction_56, "Sign typed message", NULL, "Reject", reviewContinue, reviewReject);
}

void ui_sign_712_v0(void) {
  buildFirstPage();
}
