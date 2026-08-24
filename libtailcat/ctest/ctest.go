// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ctest tests the libtailcat C bindings.
//
// It is used by libtailcat's lib_test.go, because the 'import "C"'
// directive is not allowed in test files.
package ctest

/*
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../tailcat.h"

char* derpmap_url = 0;

enum { errlen = 1024 };
char* err = NULL;

tailcat_server srv;
tailcat_client cl;

static int set_err(int handle, char tag) {
	err[0] = tag;
	err[1] = ':';
	err[2] = ' ';
	tailcat_errmsg(handle, &err[3], errlen-3);
	return 1;
}

// wait_event waits (up to ~10s) for an event whose "type" field is
// want_type on the given handle, discarding other events.
static int wait_event(int handle, const char* want_type) {
	int fd = tailcat_events_fd(handle);
	if (fd < 0) {
		snprintf(err, errlen, "wait_event(%s): bad handle", want_type);
		return 1;
	}
	char match[64];
	snprintf(match, sizeof(match), "\"type\":\"%s\"", want_type);
	char ev[512];
	for (;;) {
		int ret = tailcat_event_next(handle, ev, sizeof(ev));
		if (ret == 0) {
			if (strstr(ev, match) != NULL) {
				return 0;
			}
			continue; // some other event; keep looking
		}
		if (ret != EAGAIN) {
			snprintf(err, errlen, "event_next(%s) = %d", want_type, ret);
			return 1;
		}
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		int n = poll(&pfd, 1, 10000);
		if (n <= 0) {
			snprintf(err, errlen, "timeout waiting for %s event", want_type);
			return 1;
		}
		char hints[64];
		ssize_t discarded = read(fd, hints, sizeof(hints)); // discard wakeup hints
		(void)discarded;
	}
}

// read_full reads exactly n bytes from fd into buf.
static int read_full(int fd, char* buf, size_t n) {
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, buf+got, n-got);
		if (r <= 0) {
			snprintf(err, errlen, "read(fd %d): %zd after %zu bytes, errno %d (%s)",
				fd, r, got, errno, strerror(errno));
			return 1;
		}
		got += r;
	}
	return 0;
}

int test_conn() {
	err = calloc(errlen, 1);
	int ret;

	char priv[128];
	if ((ret = tailcat_keypair_new(priv, sizeof(priv))) != 0) {
		snprintf(err, errlen, "keypair_new = %d", ret);
		return 1;
	}
	char pub[128];
	if ((ret = tailcat_pubkey(priv, pub, sizeof(pub))) != 0) {
		snprintf(err, errlen, "pubkey = %d", ret);
		return 1;
	}
	if (strncmp(pub, "nodekey:", 8) != 0) {
		snprintf(err, errlen, "pubkey %s doesn't start with nodekey:", pub);
		return 1;
	}

	srv = tailcat_server_new(priv);
	if (srv == 0) {
		snprintf(err, errlen, "server_new failed");
		return 1;
	}
	if ((ret = tailcat_server_set_derpmap_url(srv, derpmap_url)) != 0) {
		return set_err(srv, '0');
	}
	if ((ret = tailcat_server_set_region_id(srv, 1)) != 0) {
		return set_err(srv, '1');
	}
	if ((ret = tailcat_server_set_logfd(srv, -1)) != 0) {
		return set_err(srv, '2');
	}

	// Listen before start, to exercise that ordering.
	tailcat_listener ln;
	if ((ret = tailcat_server_listen(srv, 8081, &ln)) != 0) {
		return set_err(srv, '3');
	}
	if ((ret = tailcat_server_listen(srv, 8081, &ln)) == 0) {
		snprintf(err, errlen, "duplicate listen unexpectedly succeeded");
		return 1;
	}

	if ((ret = tailcat_server_start(srv)) != 0) {
		return set_err(srv, '4');
	}

	char blob[1024];
	if ((ret = tailcat_server_connblob(srv, blob, sizeof(blob))) != 0) {
		return set_err(srv, '5');
	}
	if (strncmp(blob, "tc", 2) != 0) {
		snprintf(err, errlen, "connblob %.32s doesn't start with tc", blob);
		return 1;
	}

	cl = tailcat_client_new(blob, NULL);
	if (cl == 0) {
		snprintf(err, errlen, "client_new failed");
		return 1;
	}
	if ((ret = tailcat_client_set_derpmap_url(cl, derpmap_url)) != 0) {
		return set_err(cl, '6');
	}
	if ((ret = tailcat_client_set_logfd(cl, -1)) != 0) {
		return set_err(cl, '7');
	}

	// The handshake packet can be lost if the server's relay
	// connection is still coming up, so allow one retry.
	double latency_ms = 0;
	if ((ret = tailcat_client_connect(cl, &latency_ms)) != 0) {
		if ((ret = tailcat_client_connect(cl, &latency_ms)) != 0) {
			return set_err(cl, '8');
		}
	}
	if (latency_ms <= 0) {
		snprintf(err, errlen, "latency_ms = %f, want > 0", latency_ms);
		return 1;
	}
	if (wait_event(cl, "connected") != 0) {
		return 1;
	}
	if (wait_event(srv, "client-connected") != 0) {
		return 1;
	}

	tailcat_conn w;
	if ((ret = tailcat_client_dial(cl, 8081, &w)) != 0) {
		return set_err(cl, '9');
	}
	tailcat_conn r;
	if ((ret = tailcat_accept(ln, &r)) != 0) {
		return set_err(srv, 'a');
	}
	if (wait_event(cl, "dial-ok") != 0) {
		return 1;
	}

	// Client to server.
	const char hello[] = "hello";
	if (write(w, hello, strlen(hello)) != (ssize_t)strlen(hello)) {
		snprintf(err, errlen, "short write: errno %d (%s)", errno, strerror(errno));
		return 1;
	}
	char got[16];
	if (read_full(r, got, strlen(hello)) != 0) {
		return 1;
	}
	if (strncmp(got, hello, strlen(hello)) != 0) {
		snprintf(err, errlen, "got %.5s, want %s", got, hello);
		return 1;
	}

	// Server to client.
	const char world[] = "world";
	if (write(r, world, strlen(world)) != (ssize_t)strlen(world)) {
		snprintf(err, errlen, "short write back: errno %d (%s)", errno, strerror(errno));
		return 1;
	}
	if (read_full(w, got, strlen(world)) != 0) {
		return 1;
	}
	if (strncmp(got, world, strlen(world)) != 0) {
		snprintf(err, errlen, "got %.5s, want %s", got, world);
		return 1;
	}

	// Half-close: after the client shuts down its write side, the
	// server sees EOF but can still send, netcat style.
	if (shutdown(w, SHUT_WR) != 0) {
		snprintf(err, errlen, "shutdown: errno %d (%s)", errno, strerror(errno));
		return 1;
	}
	if (read(r, got, sizeof(got)) != 0) {
		snprintf(err, errlen, "no EOF after half-close");
		return 1;
	}
	const char bye[] = "bye!";
	if (write(r, bye, strlen(bye)) != (ssize_t)strlen(bye)) {
		snprintf(err, errlen, "write after half-close: errno %d (%s)", errno, strerror(errno));
		return 1;
	}
	if (read_full(w, got, strlen(bye)) != 0) {
		return 1;
	}
	if (strncmp(got, bye, strlen(bye)) != 0) {
		snprintf(err, errlen, "got %.4s, want %s", got, bye);
		return 1;
	}

	if (close(w) != 0 || close(r) != 0) {
		snprintf(err, errlen, "close conns: errno %d (%s)", errno, strerror(errno));
		return 1;
	}

	// Dialing a port with no listener fails with a dial-error event
	// and EOF on the connection.
	tailcat_conn bad;
	if ((ret = tailcat_client_dial(cl, 9, &bad)) != 0) {
		return set_err(cl, 'b');
	}
	if (wait_event(cl, "dial-error") != 0) {
		return 1;
	}
	if (read(bad, got, sizeof(got)) != 0) {
		snprintf(err, errlen, "no EOF on failed dial");
		return 1;
	}
	if (close(bad) != 0) {
		snprintf(err, errlen, "close bad conn: errno %d (%s)", errno, strerror(errno));
		return 1;
	}

	if (close(ln) != 0) {
		snprintf(err, errlen, "close listener: errno %d (%s)", errno, strerror(errno));
		return 1;
	}
	return 0;
}

int close_conn() {
	if (tailcat_client_close(cl) != 0) {
		return set_err(cl, 'c');
	}
	if (tailcat_client_close(cl) != EBADF) {
		snprintf(err, errlen, "double client close didn't return EBADF");
		return 1;
	}
	if (tailcat_server_close(srv) != 0) {
		return set_err(srv, 'd');
	}
	if (tailcat_server_close(srv) != EBADF) {
		snprintf(err, errlen, "double server close didn't return EBADF");
		return 1;
	}
	return 0;
}
*/
import "C"
import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

var verboseDERP = flag.Bool("verbose-derp", false, "if set, print DERP and STUN logs")

// RunTestConn runs a local DERP relay and a DERP map server for it,
// then drives the C side of the test: a tailcat server and client
// exchanging data both ways through the relay via the C API.
func RunTestConn(t *testing.T) {
	derpLogf := logger.Discard
	if *verboseDERP {
		derpLogf = t.Logf
	}
	dm := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")

	dms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(dm)
	}))
	t.Cleanup(dms.Close)
	C.derpmap_url = C.CString(dms.URL)

	if C.test_conn() != 0 {
		t.Fatal(C.GoString(C.err))
	}
	if C.close_conn() != 0 {
		t.Fatal(C.GoString(C.err))
	}
}
