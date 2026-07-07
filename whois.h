#ifndef WHOIS_H
#define WHOIS_H

#include <stddef.h>
#include <stdbool.h>
#include <talloc.h>

struct curl_buf {
	char *data;
	size_t len;
};

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata);

char *tailscale_whois(const char *ip, const char *socket_path,
		      TALLOC_CTX *mem_ctx);

/*
 * Verify that local_ip — the address the SMB client connected *to* on this
 * host — is one of this node's own Tailscale addresses, as reported by the
 * tailscaled LocalAPI /localapi/v0/status. Returns true only if tailscaled
 * confirms the match, tying the accepted connection to the Tailscale
 * interface. Fails closed (returns false) on any query or parse error.
 */
bool tailscale_local_ip_ok(const char *local_ip, const char *socket_path);

#endif
