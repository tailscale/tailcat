// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The C entry points of libtailcat. Each forwards to the Go function of the
// same name (Tailcat prefix, exported from libtailcat.go with //export),
// casting away the const that the cgo-generated declarations lack. The Go
// symbols are declared here by hand rather than by including _cgo_export.h,
// which is a build artifact, so this file is the const-correct view of them.

#include "tailcat.h"

// Functions exported by Go.
extern int TailcatErrmsg(int h, char* buf, size_t buflen);
extern int TailcatSetLogFD(int h, int fd);

extern int TailcatServerNew(void);
extern int TailcatServerSetKey(int sd, char* keyJSON);
extern int TailcatServerSetRegionID(int sd, int regionID);
extern int TailcatServerSetRelayHosts(int sd, char* hosts);
extern int TailcatServerSetDERPMapURL(int sd, char* url);
extern int TailcatServerSetEmbedRelay(int sd, int embed);
extern int TailcatServerAllowClient(int sd, char* nodekey);
extern int TailcatServerListen(int sd, int port, int* listenerOut);
extern int TailcatServerStart(int sd);
extern int TailcatServerAddr(int sd, char* buf, size_t buflen);
extern int TailcatServerPublicKey(int sd, char* buf, size_t buflen);
extern int TailcatServerStatusJSON(int sd, char** jsonOut);
extern int TailcatServerClose(int sd);

extern int TailcatAccept(int l, int* connOut);
extern int TailcatConnInfo(int l, int c, char* remoteBuf, size_t remoteBuflen, int* localPortOut);

extern int TailcatClientNew(char* addr);
extern int TailcatClientSetKey(int cd, char* keyJSON);
extern int TailcatClientSetDERPMapURL(int cd, char* url);
extern int TailcatClientPublicKey(int cd, char* buf, size_t buflen);
extern int TailcatClientPing(int cd, int timeoutMs, double* latencyMsOut);
extern int TailcatClientPathJSON(int cd, int timeoutMs, char** jsonOut);
extern int TailcatClientDial(int cd, int port, int timeoutMs, int* connOut);
extern int TailcatClientClose(int cd);

extern char* TailcatKeyGenerate(char** keyJSONOut);
extern char* TailcatKeyPublic(char* keyJSON, char** nodekeyOut);
extern char* TailcatKeyAddr(char* keyJSON, char** addrOut);
extern char* TailcatAddrParse(char* addr, char** jsonOut);
extern char* TailcatAddrResolve(char* addr, char* derpmapURL, int timeoutMs, char** addrOut);

int tailcat_errmsg(tailcat_handle h, char* buf, size_t buflen) {
	return TailcatErrmsg(h, buf, buflen);
}

int tailcat_set_logfd(tailcat_handle h, int fd) {
	return TailcatSetLogFD(h, fd);
}

tailcat_handle tailcat_server_new(void) {
	return TailcatServerNew();
}

int tailcat_server_set_key(tailcat_handle sd, const char* key_json) {
	return TailcatServerSetKey(sd, (char*)key_json);
}

int tailcat_server_set_region_id(tailcat_handle sd, int region_id) {
	return TailcatServerSetRegionID(sd, region_id);
}

int tailcat_server_set_relay_hosts(tailcat_handle sd, const char* hosts) {
	return TailcatServerSetRelayHosts(sd, (char*)hosts);
}

int tailcat_server_set_derpmap_url(tailcat_handle sd, const char* url) {
	return TailcatServerSetDERPMapURL(sd, (char*)url);
}

int tailcat_server_set_embed_relay(tailcat_handle sd, int embed) {
	return TailcatServerSetEmbedRelay(sd, embed);
}

int tailcat_server_allow_client(tailcat_handle sd, const char* nodekey) {
	return TailcatServerAllowClient(sd, (char*)nodekey);
}

int tailcat_server_listen(tailcat_handle sd, int port, tailcat_listener* listener_out) {
	return TailcatServerListen(sd, port, (int*)listener_out);
}

int tailcat_server_start(tailcat_handle sd) {
	return TailcatServerStart(sd);
}

int tailcat_server_addr(tailcat_handle sd, char* buf, size_t buflen) {
	return TailcatServerAddr(sd, buf, buflen);
}

int tailcat_server_public_key(tailcat_handle sd, char* buf, size_t buflen) {
	return TailcatServerPublicKey(sd, buf, buflen);
}

int tailcat_server_status_json(tailcat_handle sd, char** json_out) {
	return TailcatServerStatusJSON(sd, json_out);
}

int tailcat_server_close(tailcat_handle sd) {
	return TailcatServerClose(sd);
}

int tailcat_accept(tailcat_listener l, tailcat_conn* conn_out) {
	return TailcatAccept(l, (int*)conn_out);
}

int tailcat_conn_info(tailcat_listener l, tailcat_conn c, char* remote_buf, size_t remote_buflen, int* local_port_out) {
	return TailcatConnInfo(l, c, remote_buf, remote_buflen, local_port_out);
}

tailcat_handle tailcat_client_new(const char* addr) {
	return TailcatClientNew((char*)addr);
}

int tailcat_client_set_key(tailcat_handle cd, const char* key_json) {
	return TailcatClientSetKey(cd, (char*)key_json);
}

int tailcat_client_set_derpmap_url(tailcat_handle cd, const char* url) {
	return TailcatClientSetDERPMapURL(cd, (char*)url);
}

int tailcat_client_public_key(tailcat_handle cd, char* buf, size_t buflen) {
	return TailcatClientPublicKey(cd, buf, buflen);
}

int tailcat_client_ping(tailcat_handle cd, int timeout_ms, double* latency_ms_out) {
	return TailcatClientPing(cd, timeout_ms, latency_ms_out);
}

int tailcat_client_path_json(tailcat_handle cd, int timeout_ms, char** json_out) {
	return TailcatClientPathJSON(cd, timeout_ms, json_out);
}

int tailcat_client_dial(tailcat_handle cd, int port, int timeout_ms, tailcat_conn* conn_out) {
	return TailcatClientDial(cd, port, timeout_ms, (int*)conn_out);
}

int tailcat_client_close(tailcat_handle cd) {
	return TailcatClientClose(cd);
}

char* tailcat_key_generate(char** key_json_out) {
	return TailcatKeyGenerate(key_json_out);
}

char* tailcat_key_public(const char* key_json, char** nodekey_out) {
	return TailcatKeyPublic((char*)key_json, nodekey_out);
}

char* tailcat_key_addr(const char* key_json, char** addr_out) {
	return TailcatKeyAddr((char*)key_json, addr_out);
}

char* tailcat_addr_parse(const char* addr, char** json_out) {
	return TailcatAddrParse((char*)addr, json_out);
}

char* tailcat_addr_resolve(const char* addr, const char* derpmap_url, int timeout_ms, char** addr_out) {
	return TailcatAddrResolve((char*)addr, (char*)derpmap_url, timeout_ms, addr_out);
}
