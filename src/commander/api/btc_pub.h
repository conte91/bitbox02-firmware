#ifndef _API_BTC_H
#define _API_BTC_H

#include <stdlib.h>

#include "../commander.h"

typedef struct {
    char* pub;
    size_t pub_len;
    bool result;
    commander_error_t reply;
    char title[100];
    enum {
        COMMANDER_BTC_PUB_STARTED,
        COMMANDER_BTC_PUB_CONFIRMED,
        COMMANDER_BTC_PUB_ABORTED
    } state;
} btc_pub_data_t;

void abort_btc_pub(void);

void process_btc_pub(void);

commander_error_t btc_pub_xpub(const BTCPubRequest* request, PubResponse* response);

commander_error_t btc_pub_address_simple(const BTCPubRequest* request, PubResponse* response);

#endif // _API_BTC_H
