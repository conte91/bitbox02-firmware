#include "btc_pub.h"

#include <apps/btc/btc.h>
#include <apps/btc/btc_sign.h>
#include <ui/workflow_stack.h>
#include <wally_bip32.h> // for BIP32_INITIAL_HARDENED_CHILD
#include <workflow/confirm.h>

#include "api_state.h"
#include "../commander_timeout.h"

static const char* _coin_btc = "Bitcoin";
static const char* _coin_tbtc = "BTC Testnet";
static const char* _coin_ltc = "Litecoin";
static const char* _coin_tltc = "LTC Testnet";

// Returns the string to be used in the confirm title. Returns NULL for an invalid coin.
static const char* _coin_title(BTCCoin coin)
{
    switch (coin) {
    case BTCCoin_BTC:
        return _coin_btc;
    case BTCCoin_TBTC:
        return _coin_tbtc;
    case BTCCoin_LTC:
        return _coin_ltc;
    case BTCCoin_TLTC:
        return _coin_tltc;
    default:
        return NULL;
    }
}


static bool _init_btc_pub_state(PubResponse* response) {
    btc_pub_data_t* data = &get_commander_api_state()->data.btc_pub;
    data->pub = malloc(sizeof(response->pub));
    if (!data->pub) {
        return false;
    }
    data->pub_len = sizeof(response->pub);
    data->state = COMMANDER_BTC_PUB_STARTED;
    return true;
}

static void _clean_btc_pub_state(void)
{
    btc_pub_data_t* data = &get_commander_api_state()->data.btc_pub;
    free(data->pub);
}

static void _clean_btc_pub(void) {
    _clean_btc_pub_state();
    get_commander_api_state()->status = COMMANDER_STATUS_IDLE;
}

#define BTC_PUB_TIMEOUT (50)

static void _btc_pub_done(bool result, void* param)
{
    (void)param;
    btc_pub_data_t* data = &get_commander_api_state()->data.btc_pub;
    if (result) {
        data->state = COMMANDER_BTC_PUB_CONFIRMED;
    } else {
        data->state = COMMANDER_BTC_PUB_ABORTED;
    }
}

void abort_btc_pub(void)
{
    /* Destroy this workflow. */
    workflow_stack_stop_workflow();
    _clean_btc_pub();
}

/**
 * Called at every loop, when we are asking the user to confirm
 * the device name.
 */
void process_btc_pub(void)
{
    if (commander_timeout_get_timer() > BTC_PUB_TIMEOUT) {
        abort_set_device_name();
    }
}

commander_error_t btc_pub_xpub(const BTCPubRequest* request, PubResponse* response)
{
    commander_api_state_t* api_state = get_commander_api_state();

    if (api_state->status == COMMANDER_STATUS_BTC_PUB) {
        btc_pub_data_t* data = &api_state->data.btc_pub;
        commander_error_t result = COMMANDER_STARTED;
        if (data->state == COMMANDER_BTC_PUB_CONFIRMED) {
            _clean_btc_pub();
            memcpy(response->pub, data->pub, data->pub_len);
            result = COMMANDER_OK;
        } else if (data->state == COMMANDER_BTC_PUB_ABORTED) {
            _clean_btc_pub();
            result = COMMANDER_ERR_USER_ABORT;
        }
        return result;
    }

    if (api_state->status == COMMANDER_STATUS_IDLE) {
        btc_pub_data_t* data = &api_state->data.btc_pub;
        if (!_init_btc_pub_state(response)) {
            return COMMANDER_ERR_GENERIC;
        }
        if (!app_btc_xpub(
                request->coin,
                request->output.xpub_type,
                request->keypath,
                request->keypath_count,
                data->pub,
                data->pub_len)) {
            _clean_btc_pub_state();
            return COMMANDER_ERR_GENERIC;
        }
        if (request->display) {
            const char* coin = _coin_title(request->coin);
            if (coin == NULL) {
                _clean_btc_pub_state();
                return COMMANDER_ERR_GENERIC;
            }
            switch (request->output.xpub_type) {
            case BTCPubRequest_XPubType_TPUB:
            case BTCPubRequest_XPubType_XPUB:
            case BTCPubRequest_XPubType_YPUB:
            case BTCPubRequest_XPubType_ZPUB:
            case BTCPubRequest_XPubType_VPUB:
            case BTCPubRequest_XPubType_UPUB:
            case BTCPubRequest_XPubType_CAPITAL_VPUB:
            case BTCPubRequest_XPubType_CAPITAL_ZPUB:
                snprintf(
                    data->title,
                    sizeof(data->title),
                    "%s\naccount #%lu",
                    coin,
                    (unsigned long)request->keypath[2] - BIP32_INITIAL_HARDENED_CHILD + 1);
                break;
            default:
                _clean_btc_pub_state();
                return COMMANDER_ERR_GENERIC;
            }
            api_state->status = COMMANDER_STATUS_BTC_PUB;
            workflow_stack_start_workflow(
                workflow_confirm_scrollable(
                    data->title,
                    data->pub,
                    NULL,
                    false,
                    _btc_pub_done,
                    NULL
                )
            );
            return COMMANDER_STARTED;
        } else {
            memcpy(response->pub, data->pub, data->pub_len);
            _clean_btc_pub_state();
            return COMMANDER_OK;
        }
    }

    /* Can't receive this command now. */
    return COMMANDER_ERR_INVALID_STATE;
}

commander_error_t btc_pub_address_simple(const BTCPubRequest* request, PubResponse* response)
{
    commander_api_state_t* api_state = get_commander_api_state();

    if (api_state->status == COMMANDER_STATUS_BTC_PUB) {
        btc_pub_data_t* data = &api_state->data.btc_pub;
        commander_error_t result = COMMANDER_STARTED;
        if (data->state == COMMANDER_BTC_PUB_CONFIRMED) {
            _clean_btc_pub();
            memcpy(response->pub, data->pub, data->pub_len);
            result = COMMANDER_OK;
        } else if (data->state == COMMANDER_BTC_PUB_ABORTED) {
            _clean_btc_pub();
            result = COMMANDER_ERR_USER_ABORT;
        }
        return result;
    }

    if (api_state->status == COMMANDER_STATUS_IDLE) {
        btc_pub_data_t* data = &api_state->data.btc_pub;
        if (!_init_btc_pub_state(response)) {
            return COMMANDER_ERR_GENERIC;
        }
        if (!app_btc_address_simple(
                request->coin,
                request->output.script_config.config.simple_type,
                request->keypath,
                request->keypath_count,
                data->pub,
                data->pub_len)) {
            _clean_btc_pub_state();
            return COMMANDER_ERR_GENERIC;
        }
        if (request->display) {
            const char* coin = _coin_title(request->coin);
            if (coin == NULL) {
                _clean_btc_pub_state();
                return COMMANDER_ERR_GENERIC;
            }
            switch (request->output.script_config.config.simple_type) {
            case BTCScriptConfig_SimpleType_P2WPKH_P2SH:
                snprintf(data->title, sizeof(data->title), "%s", coin);
                break;
            case BTCScriptConfig_SimpleType_P2WPKH:
                snprintf(data->title, sizeof(data->title), "%s\nbech32", coin);
                break;
            default:
                _clean_btc_pub_state();
                return COMMANDER_ERR_GENERIC;
            }
            api_state->status = COMMANDER_STATUS_BTC_PUB;
            workflow_stack_start_workflow(
                workflow_confirm_scrollable(
                    data->title,
                    data->pub,
                    NULL,
                    false,
                    _btc_pub_done,
                    NULL
                )
            );
            return COMMANDER_STARTED;
        } else {
            memcpy(response->pub, data->pub, data->pub_len);
            _clean_btc_pub_state();
            return COMMANDER_OK;
        }
    }

    /* Can't receive this command now. */
    return COMMANDER_ERR_INVALID_STATE;
}
