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

/*
 * The identity tailscaled reports for a peer.
 *
 * A tagged node has no personal owner: the control plane reports its
 * UserProfile.LoginName as the shared tag namespace ("tagged-devices") and
 * carries the node's actual tags in Node.Tags. Both are exposed so callers
 * can key an access map off either — a "tag:foo" key distinguishes one tagged
 * node from another, whereas the login name of every tagged node is identical.
 *
 * All strings are allocated on the mem_ctx passed to tailscale_whois().
 */
struct tailscale_identity {
	/* UserProfile.LoginName, or NULL if the response carried none. */
	const char *login_name;
	/* Node.Tags as a NULL-terminated array, or NULL if the node has none. */
	const char **tags;
};

/*
 * Ask tailscaled who owns `ip`. Returns true and fills `out` if the peer
 * resolved to an identity — meaning at least one of login_name or tags is
 * set. Returns false (leaving `out` untouched) if the address is not a known
 * peer, or on any query or parse error.
 */
bool tailscale_whois(const char *ip, const char *socket_path,
		     TALLOC_CTX *mem_ctx, struct tailscale_identity *out);

/*
 * Verify that local_ip — the address the SMB client connected *to* on this
 * host — is one of this node's own Tailscale addresses, as reported by the
 * tailscaled LocalAPI /localapi/v0/status. Returns true only if tailscaled
 * confirms the match, tying the accepted connection to the Tailscale
 * interface. Fails closed (returns false) on any query or parse error.
 */
bool tailscale_local_ip_ok(const char *local_ip, const char *socket_path);

#endif
