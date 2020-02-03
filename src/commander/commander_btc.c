// Copyright 2019 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "commander_btc.h"
#include "commander_states.h"

#include <stdio.h>

#include <apps/btc/btc.h>
#include <apps/btc/btc_sign.h>
#include <workflow/verify_pub.h>

#include "api/btc_pub.h"

commander_error_t commander_btc_pub(const BTCPubRequest* request, PubResponse* response)
{
    if (!app_btc_enabled(request->coin)) {
        return COMMANDER_ERR_DISABLED;
    }
    switch (request->which_output) {
    case BTCPubRequest_xpub_type_tag:
        return btc_pub_xpub(request, response);
    case BTCPubRequest_script_config_tag:
        switch (request->output.script_config.which_config) {
        case BTCScriptConfig_simple_type_tag:
            return btc_pub_address_simple(request, response);
        default:
            return COMMANDER_ERR_INVALID_INPUT;
        }
    default:
        return COMMANDER_ERR_INVALID_INPUT;
    }
}

commander_error_t commander_btc_sign(const Request* request, Response* response)
{
    response->which_response = Response_btc_sign_next_tag;
    app_btc_sign_error_t result;
    switch (request->which_request) {
    case Request_btc_sign_init_tag:
        if (!app_btc_enabled(request->request.btc_sign_init.coin)) {
            return COMMANDER_ERR_DISABLED;
        }
        result =
            app_btc_sign_init(&(request->request.btc_sign_init), &response->response.btc_sign_next);
        break;
    case Request_btc_sign_input_tag:
        result = app_btc_sign_input(
            &(request->request.btc_sign_input), &response->response.btc_sign_next);
        break;
    case Request_btc_sign_output_tag:
        result = app_btc_sign_output(
            &(request->request.btc_sign_output), &response->response.btc_sign_next);
        break;
    default:
        return COMMANDER_ERR_GENERIC;
    }
    if (result == APP_BTC_SIGN_ERR_USER_ABORT) {
        return COMMANDER_ERR_USER_ABORT;
    }
    if (result != APP_BTC_SIGN_OK) {
        return COMMANDER_ERR_GENERIC;
    }
    switch (response->response.btc_sign_next.type) {
    case BTCSignNextResponse_Type_INPUT:
        commander_states_force_next(Request_btc_sign_input_tag);
        break;
    case BTCSignNextResponse_Type_OUTPUT:
        commander_states_force_next(Request_btc_sign_output_tag);
        break;
    default:
        break;
    }
    return COMMANDER_OK;
}
