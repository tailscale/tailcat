// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#include "tailcat.h"

// Functions exported by Go (see libtailcat.go).
extern int TailcatKeypairNew(char* buf, size_t buflen);
extern int TailcatPubkey(char* privkey, char* buf, size_t buflen);
extern int TailcatServerNew(char* privkey);
extern int TailcatServerSetDerpmapURL(int s, char* url);
extern int TailcatServerSetRegionID(int s, int regionID);
extern int TailcatServerSetLogFD(int s, int fd);
extern int TailcatServerStart(int s);
extern int TailcatServerConnblob(int s, char* buf, size_t buflen);
extern int TailcatServerListen(int s, int port, int* listenerOut);
extern int TailcatAccept(int listenerFD, int* connOut);
extern int TailcatServerClose(int s);
extern int TailcatClientNew(char* connblob, char* privkey);
extern int TailcatClientSetDerpmapURL(int c, char* url);
extern int TailcatClientSetLogFD(int c, int fd);
extern int TailcatClientConnect(int c, double* latencyMsOut);
extern int TailcatClientDial(int c, int port, int* connOut);
extern int TailcatClientClose(int c);
extern int TailcatEventsFD(int handle);
extern int TailcatEventNext(int handle, char* buf, size_t buflen);
extern int TailcatErrmsg(int handle, char* buf, size_t buflen);

int tailcat_keypair_new(char* buf, size_t buflen) {
	return TailcatKeypairNew(buf, buflen);
}

int tailcat_pubkey(const char* privkey, char* buf, size_t buflen) {
	return TailcatPubkey((char*)privkey, buf, buflen);
}

tailcat_server tailcat_server_new(const char* privkey) {
	return TailcatServerNew((char*)privkey);
}

int tailcat_server_set_derpmap_url(tailcat_server s, const char* url) {
	return TailcatServerSetDerpmapURL(s, (char*)url);
}

int tailcat_server_set_region_id(tailcat_server s, int region_id) {
	return TailcatServerSetRegionID(s, region_id);
}

int tailcat_server_set_logfd(tailcat_server s, int fd) {
	return TailcatServerSetLogFD(s, fd);
}

int tailcat_server_start(tailcat_server s) {
	return TailcatServerStart(s);
}

int tailcat_server_connblob(tailcat_server s, char* buf, size_t buflen) {
	return TailcatServerConnblob(s, buf, buflen);
}

int tailcat_server_listen(tailcat_server s, int port, tailcat_listener* listener_out) {
	return TailcatServerListen(s, port, (int*)listener_out);
}

int tailcat_accept(tailcat_listener l, tailcat_conn* conn_out) {
	return TailcatAccept(l, (int*)conn_out);
}

int tailcat_server_close(tailcat_server s) {
	return TailcatServerClose(s);
}

tailcat_client tailcat_client_new(const char* connblob, const char* privkey) {
	return TailcatClientNew((char*)connblob, (char*)privkey);
}

int tailcat_client_set_derpmap_url(tailcat_client c, const char* url) {
	return TailcatClientSetDerpmapURL(c, (char*)url);
}

int tailcat_client_set_logfd(tailcat_client c, int fd) {
	return TailcatClientSetLogFD(c, fd);
}

int tailcat_client_connect(tailcat_client c, double* latency_ms_out) {
	return TailcatClientConnect(c, latency_ms_out);
}

int tailcat_client_dial(tailcat_client c, int port, tailcat_conn* conn_out) {
	return TailcatClientDial(c, port, (int*)conn_out);
}

int tailcat_client_close(tailcat_client c) {
	return TailcatClientClose(c);
}

int tailcat_events_fd(int handle) {
	return TailcatEventsFD(handle);
}

int tailcat_event_next(int handle, char* buf, size_t buflen) {
	return TailcatEventNext(handle, buf, buflen);
}

int tailcat_errmsg(int handle, char* buf, size_t buflen) {
	return TailcatErrmsg(handle, buf, buflen);
}
