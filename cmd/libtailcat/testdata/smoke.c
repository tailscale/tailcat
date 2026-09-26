/* Copyright (c) Tailscale Inc & contributors
 * SPDX-License-Identifier: BSD-3-Clause */
#include "tailcat.h"
#include <assert.h>
#include <string.h>

int main(void) {
    assert(tc_abi_version() == 1);
    char *error = NULL;
    char *keys = NULL;
    assert(tc_key_generate(&keys, &error) == TC_OK);
    assert(error == NULL && strstr(keys, "private_key") != NULL);
    tc_free(keys);

    tc_handle server = 0;
    tc_token token = TC_NO_CANCEL;
    assert(tc_server_new("{}", &server, &error) == TC_OK);
    assert(server != 0 && error == NULL);
    assert(TC_NO_CANCEL == 0);
    assert(tc_drain(server, TC_NO_CANCEL, &error) == TC_OK);
    assert(error == NULL);
    assert(tc_token_cancel(TC_NO_CANCEL, &error) == TC_CLOSED);
    assert(error != NULL);
    tc_free(error);
    assert(tc_close(TC_NO_CANCEL, &error) == TC_CLOSED);
    assert(error != NULL);
    tc_free(error);
    /* Rejecting the sentinel must not affect the server. */
    assert(tc_drain(server, TC_NO_CANCEL, &error) == TC_OK);
    assert(error == NULL);
    assert(tc_token_new(-1, &token, &error) == TC_OK);
    assert(tc_drain(server, token, &error) == TC_OK);
    assert(tc_token_cancel(token, &error) == TC_OK);
    assert(tc_close(token, &error) == TC_OK);
    assert(tc_close(server, &error) == TC_OK);
    assert(tc_close(server, &error) == TC_CLOSED);
    assert(error != NULL);
    tc_free(error);

    tc_handle client = 42;
    assert(tc_client_new("{\"address\":\"secret\"}", &client, &error) == TC_INVALID_ARGUMENT);
    assert(client == 0 && strstr(error, "secret") == NULL);
    tc_free(error);

    int32_t ping_ms = -1;
    assert(tc_client_ping(0, TC_NO_CANCEL, &ping_ms, &error) == TC_CLOSED);
    assert(ping_ms == 0 && error != NULL);
    tc_free(error);
    assert(tc_client_ping(0, TC_NO_CANCEL, NULL, &error) == TC_INVALID_ARGUMENT);
    tc_free(error);

    char previous[] = "previous result";
    char *disco_json = previous;
    assert(tc_client_disco_ping(0, TC_NO_CANCEL, &disco_json, &error) == TC_CLOSED);
    assert(disco_json == NULL && error != NULL);
    tc_free(error);
    assert(tc_client_disco_ping(0, TC_NO_CANCEL, NULL, &error) == TC_INVALID_ARGUMENT);
    tc_free(error);
    return 0;
}
