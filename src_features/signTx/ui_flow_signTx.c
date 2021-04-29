#include "shared_context.h"
#include "ui_callbacks.h"

// clang-format off
UX_STEP_NOCB(
    ux_confirm_selector_flow_1_step,
    pnn,
    {
      &C_icon_eye,
      "Verify",
      "selector",
    });

UX_STEP_NOCB(
    ux_confirm_selector_flow_2_step,
    bn,
    {
      "Selector",
      strings.tmp.tmp
    });
UX_STEP_CB(
    ux_confirm_selector_flow_3_step,
    pb,
    io_seproxyhal_touch_data_ok(NULL),
    {
      &C_icon_validate_14,
      "Approve",
    });
UX_STEP_CB(
    ux_confirm_selector_flow_4_step,
    pb,
    io_seproxyhal_touch_data_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });
// clang-format on

UX_FLOW(ux_confirm_selector_flow,
        &ux_confirm_selector_flow_1_step,
        &ux_confirm_selector_flow_2_step,
        &ux_confirm_selector_flow_3_step,
        &ux_confirm_selector_flow_4_step);

//////////////////////////////////////////////////////////////////////
// clang-format off
UX_STEP_NOCB(
    ux_confirm_parameter_flow_1_step,
    pnn,
    {
      &C_icon_eye,
      "Verify",
      strings.tmp.tmp2
    });
UX_STEP_NOCB(
    ux_confirm_parameter_flow_2_step,
    bnnn_paging,
    {
      .title = "Parameter",
      .text = strings.tmp.tmp,
    });
UX_STEP_CB(
    ux_confirm_parameter_flow_3_step,
    pb,
    io_seproxyhal_touch_data_ok(NULL),
    {
      &C_icon_validate_14,
      "Approve",
    });
UX_STEP_CB(
    ux_confirm_parameter_flow_4_step,
    pb,
    io_seproxyhal_touch_data_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });
// clang-format on

UX_FLOW(ux_confirm_parameter_flow,
        &ux_confirm_parameter_flow_1_step,
        &ux_confirm_parameter_flow_2_step,
        &ux_confirm_parameter_flow_3_step,
        &ux_confirm_parameter_flow_4_step);

//////////////////////////////////////////////////////////////////////
// clang-format off
UX_STEP_NOCB(ux_approval_tx_1_step,
    pnn,
    {
      &C_icon_eye,
      "Review",
      "transaction",
    });
UX_STEP_NOCB(
    ux_approval_tx_2_step,
    bnnn_paging,
    {
      .title = "Amount",
      .text = strings.common.fullAmount
    });
UX_STEP_NOCB(
    ux_approval_tx_3_step,
    bnnn_paging,
    {
      .title = "Address",
      .text = strings.common.fullAddress,
    });
UX_STEP_NOCB(
    ux_approval_tx_4_step,
    bnnn_paging,
    {
      .title = "Max Fees",
      .text = strings.common.maxFee,
    });
UX_STEP_CB(
    ux_approval_tx_5_step,
    pbb,
    io_seproxyhal_touch_tx_ok(NULL),
    {
      &C_icon_validate_14,
      "Accept",
      "and send",
    });
UX_STEP_CB(
    ux_approval_tx_6_step,
    pb,
    io_seproxyhal_touch_tx_cancel(NULL),
    {
      &C_icon_crossmark,
      "Reject",
    });

UX_STEP_NOCB(
    ux_approval_tx_display_nonce_step,
    bnnn_paging,
    {
      .title = "Nonce",
      .text = strings.common.nonce,
    });

UX_STEP_NOCB(ux_approval_tx_data_warning_step,
    pbb,
    {
      &C_icon_warning,
      "Data",
      "Present",
    });
// clang-format on

const ux_flow_step_t *ux_approval_tx_flow_[9];

void ux_approve_tx(bool dataPresent) {
    int step = 0;
    ux_approval_tx_flow_[step++] = &ux_approval_tx_1_step;
    if (dataPresent && !N_storage.contractDetails) {
        ux_approval_tx_flow_[step++] = &ux_approval_tx_data_warning_step;
    }
    ux_approval_tx_flow_[step++] = &ux_approval_tx_2_step;
    ux_approval_tx_flow_[step++] = &ux_approval_tx_3_step;
    if (N_storage.displayNonce) {
        ux_approval_tx_flow_[step++] = &ux_approval_tx_display_nonce_step;
    }
    ux_approval_tx_flow_[step++] = &ux_approval_tx_4_step;
    ux_approval_tx_flow_[step++] = &ux_approval_tx_5_step;
    ux_approval_tx_flow_[step++] = &ux_approval_tx_6_step;
    ux_approval_tx_flow_[step++] = FLOW_END_STEP;

    ux_flow_init(0, ux_approval_tx_flow_, NULL);
}