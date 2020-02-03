#ifndef _API_BTC_H
#define _API_BTC_H

#include <stdlib.h>

#include "../commander.h"

void abort_btc_pub(void);

void process_btc_pub(void);

commander_error_t btc_pub_xpub(const BTCPubRequest* request, PubResponse* response);

commander_error_t btc_pub_address_simple(const BTCPubRequest* request, PubResponse* response);

#endif // _API_BTC_H
