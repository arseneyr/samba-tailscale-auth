/*
 * vfs_tailscale — Samba VFS module for Tailscale identity-based access.
 *
 * Loaded via "vfs objects" on a share configured for guest access.
 * On VFS connect, queries tailscaled whois for the client IP, maps
 * to a local user, and replaces conn->session_info so that file
 * operations run as that user.
 *
 * Samba symbols (smb_register_vfs, smb_vfs_call_connect,
 * make_session_info_from_username, tsocket_address_inet_addr_string)
 * resolve at runtime from smbd's address space — no samba link needed.
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <talloc.h>

#include "whois.h"

/* Samba public header for NTSTATUS */
#define HAVE_IMMEDIATE_STRUCTURES 1
#include <core/ntstatus.h>

/*
 * Vendored private struct declarations from samba 4.23.8
 * (source3/include/vfs.h, source3/smbd/globals.h).
 *
 * Only fields up to the ones we access are defined.  We never allocate
 * these structs — we only chase pointers into smbd's existing copies.
 *
 * Verified against samba-4.23.8 source3/include/vfs.h: connection_struct,
 * vfs_handle_struct and vfs_fn_pointers (98 fn slots, connect_fn/disconnect_fn
 * first) are byte-identical to 4.22.6; only SMB_VFS_INTERFACE_VERSION changed
 * (50 -> 51).
 */

#define SMB_VFS_INTERFACE_VERSION 51

/* Opaque types we only use as pointers */
struct tsocket_address;
struct smbXsrv_tcon;
struct share_params { int service; };
struct vuid_cache;
struct files_struct;
struct vfs_handle_struct;
struct security_token;

/*
 * librpc/gen_ndr/security.h — first field only.  We only ever read
 * ->uid (offset 0) to reject a mapping that resolves to a privileged
 * account.
 */
struct security_unix_token {
	uid_t uid;
};

/*
 * librpc/gen_ndr/auth.h — fields through unix_token.  Verified against
 * samba-4.23.8 gen_ndr/auth.h: security_token is the first pointer,
 * unix_token the second.
 */
struct auth_session_info {
	struct security_token *security_token;
	struct security_unix_token *unix_token;
};

/* source3/smbd/globals.h — first 2 fields */
struct smbd_server_connection {
	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;
};

/* source3/include/vfs.h — fields through session_info */
typedef struct connection_struct {
	struct connection_struct *next, *prev;
	struct smbd_server_connection *sconn;
	struct smbXsrv_tcon *tcon;
	uint32_t cnum;
	struct share_params *params;
	bool force_user;
	struct vuid_cache *vuid_cache;
	bool printer;
	bool ipc;
	bool read_only;
	bool have_proc_fds;
	uint64_t open_how_resolve;
	uint32_t share_access;
	int ts_res; /* enum timestamp_set_resolution */
	char *connectpath;
	struct files_struct *cwd_fsp;
	bool tcon_done;
	struct vfs_handle_struct *vfs_handles;
	struct auth_session_info *session_info;
} connection_struct;

/* source3/include/vfs.h — 98 function pointer slots */
struct vfs_fn_pointers {
	int (*connect_fn)(struct vfs_handle_struct *handle,
			  const char *service, const char *user);
	void (*disconnect_fn)(struct vfs_handle_struct *handle);
	void *_padding[96];
};

/* source3/include/vfs.h — full definition */
typedef struct vfs_handle_struct {
	struct vfs_handle_struct *next, *prev;
	const char *param;
	connection_struct *conn;
	const struct vfs_fn_pointers *fns;
	void *data;
	void (*free_data)(void **data);
} vfs_handle_struct;

/* Extern samba symbols (resolved at runtime from smbd) */
extern NTSTATUS smb_register_vfs(int version, const char *name,
				 const struct vfs_fn_pointers *fns);

extern int smb_vfs_call_connect(struct vfs_handle_struct *handle,
				const char *service, const char *user);

extern const char *tsocket_address_inet_addr_string(
			const struct tsocket_address *addr,
			TALLOC_CTX *mem_ctx);

extern NTSTATUS make_session_info_from_username(TALLOC_CTX *mem_ctx,
						const char *username,
						bool is_guest,
						struct auth_session_info **session_info);

extern NTSTATUS vfs_default_init(TALLOC_CTX *ctx);

extern const char *lp_parm_const_string(int snum, const char *type,
					 const char *option, const char *def);

#define DEFAULT_TAILSCALE_SOCKET "/var/run/tailscale/tailscaled.sock"

/* --- User map lookup --- */

/*
 * Look up an identity key in the user map string. The key is either a
 * tailscale login name or a tag ("tag:infra").
 * Map format: "key=linuxuser key2=linuxuser2"
 * Returns talloc'd linux username if found, NULL otherwise.
 */
static const char *lookup_user_map(const char *map_str,
				   const char *key,
				   TALLOC_CTX *mem_ctx)
{
	const char *p = map_str;
	size_t key_wanted_len = strlen(key);

	while (*p) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;

		const char *eq = strchr(p, '=');
		if (!eq)
			break;

		const char *val_start = eq + 1;
		const char *val_end = val_start;
		while (*val_end && *val_end != ' ' && *val_end != '\t')
			val_end++;

		size_t key_len = eq - p;
		if (key_len == key_wanted_len &&
		    strncmp(p, key, key_len) == 0) {
			size_t val_len = val_end - val_start;
			if (val_len > 0)
				return talloc_strndup(mem_ctx, val_start,
						      val_len);
		}

		p = val_end;
	}

	return NULL;
}

/*
 * Resolve a peer identity to a local user via the map.
 *
 * Tags are tried before the login name: every tagged node in the tailnet
 * shares one login name (the tag namespace, "tagged-devices" on headscale),
 * so a "tag:foo" key is both more specific and the only way to tell one
 * tagged node's access from another's. On success *matched_key points at the
 * map key that hit, for logging.
 */
static const char *resolve_local_user(const char *user_map,
				      const struct tailscale_identity *id,
				      const char **matched_key,
				      TALLOC_CTX *mem_ctx)
{
	const char *local_user;
	size_t i;

	for (i = 0; id->tags && id->tags[i]; i++) {
		local_user = lookup_user_map(user_map, id->tags[i], mem_ctx);
		if (local_user) {
			*matched_key = id->tags[i];
			return local_user;
		}
	}

	if (id->login_name) {
		local_user = lookup_user_map(user_map, id->login_name, mem_ctx);
		if (local_user) {
			*matched_key = id->login_name;
			return local_user;
		}
	}

	return NULL;
}

/* Render an identity for a log line, e.g. `tagged-devices [tag:infra]`. */
static const char *describe_identity(const struct tailscale_identity *id,
				     TALLOC_CTX *mem_ctx)
{
	char *desc = talloc_strdup(mem_ctx,
				   id->login_name ? id->login_name : "(no user)");
	size_t i;

	for (i = 0; desc && id->tags && id->tags[i]; i++)
		desc = talloc_asprintf_append(desc, "%s%s",
					      i == 0 ? " [" : ",",
					      id->tags[i]);
	if (desc && id->tags)
		desc = talloc_strdup_append(desc, "]");

	return desc ? desc : "(unknown)";
}

/* --- VFS connect implementation --- */

static int tailscale_connect(vfs_handle_struct *handle,
			     const char *service, const char *user)
{
	connection_struct *conn = handle->conn;
	const char *ip;
	const char *local_ip;
	const char *socket_path;
	struct tailscale_identity identity;
	const char *matched_key = NULL;
	const char *local_user;
	struct auth_session_info *old_session_info;
	struct auth_session_info *new_session_info = NULL;
	NTSTATUS status;
	int ret;

	/* Socket path from module parameter, or default */
	socket_path = handle->param;
	if (!socket_path || !*socket_path)
		socket_path = DEFAULT_TAILSCALE_SOCKET;

	/* Verify the connection actually arrived on our Tailscale interface:
	 * the address the client connected *to* must be one of this node's own
	 * Tailscale IPs. A whois lookup alone is not sufficient — tailscaled
	 * resolves a peer IP to an identity regardless of the interface the
	 * packet arrived on, so a spoofed peer source address on another
	 * interface could otherwise be accepted. */
	local_ip = tsocket_address_inet_addr_string(conn->sconn->local_address,
						    conn);
	if (!local_ip || !tailscale_local_ip_ok(local_ip, socket_path)) {
		syslog(LOG_WARNING,
		       "vfs_tailscale: denying connection to non-tailscale local address %s",
		       local_ip ? local_ip : "(unknown)");
		errno = EACCES;
		return -1;
	}

	/* Get client IP */
	ip = tsocket_address_inet_addr_string(conn->sconn->remote_address,
					      conn);
	if (!ip) {
		syslog(LOG_ERR, "vfs_tailscale: failed to get client IP");
		errno = EACCES;
		return -1;
	}

	/* Query tailscaled for the identity of this peer */
	if (!tailscale_whois(ip, socket_path, conn, &identity)) {
		syslog(LOG_WARNING,
		       "vfs_tailscale: denying %s — not a tailscale peer", ip);
		errno = EACCES;
		return -1;
	}

	/* A user map is mandatory: without it the raw, tailnet-controlled login
	 * name would be used directly as a Unix username, so a login name that
	 * collides with a local account (e.g. root) would be impersonated.
	 * Require an explicit admin-configured mapping instead. */
	const char *user_map = lp_parm_const_string(
		conn->params->service, "tailscale", "user map", NULL);
	if (!user_map) {
		syslog(LOG_ERR,
		       "vfs_tailscale: denying %s — no 'tailscale:user map' configured for this share",
		       ip);
		errno = EACCES;
		return -1;
	}

	local_user = resolve_local_user(user_map, &identity, &matched_key, conn);
	if (!local_user) {
		syslog(LOG_WARNING, "vfs_tailscale: no mapping for %s",
		       describe_identity(&identity, conn));
		errno = EACCES;
		return -1;
	}
	syslog(LOG_INFO, "vfs_tailscale: %s -> %s (matched %s, mapped to %s)",
	       ip, describe_identity(&identity, conn), matched_key, local_user);

	/* Build a new session_info for the mapped user */
	status = make_session_info_from_username(conn, local_user, false,
						 &new_session_info);
	if (!NT_STATUS_IS_OK(status)) {
		syslog(LOG_ERR,
		       "vfs_tailscale: make_session_info_from_username(%s) failed",
		       local_user);
		errno = EPERM;
		return -1;
	}

	/* Refuse to impersonate uid 0: a mapping that resolves to root would
	 * run all file operations with full privilege, defeating the per-user
	 * Unix permission enforcement this module relies on. */
	if (new_session_info->unix_token->uid == 0) {
		syslog(LOG_ERR,
		       "vfs_tailscale: refusing to map %s to uid 0 (%s)",
		       matched_key, local_user);
		talloc_free(new_session_info);
		errno = EPERM;
		return -1;
	}

	/* Replace the guest session with the real user before default VFS
	 * connect, so that its chdir() into the share root runs as the
	 * mapped user and Unix permissions are enforced by the kernel. */
	old_session_info = conn->session_info;
	conn->session_info = new_session_info;
	conn->force_user = true;

	/* Chain to the default VFS — chdir as the real user */
	ret = smb_vfs_call_connect(handle->next, service, user);
	if (ret < 0) {
		/* Restore original session on failure */
		conn->session_info = old_session_info;
		conn->force_user = false;
		talloc_free(new_session_info);
		return ret;
	}

	talloc_free(old_session_info);
	return 0;
}

static struct vfs_fn_pointers vfs_tailscale_fns = {
	.connect_fn = tailscale_connect,
};

NTSTATUS samba_init_module(TALLOC_CTX *ctx)
{
	/*
	 * When loaded via "preload modules", our smb_register_vfs() call
	 * sets the global backends list non-NULL.  Samba's static_init_vfs
	 * (which registers the default VFS) only runs if backends == NULL,
	 * so the default VFS never gets registered and smbd crashes.
	 * Fix: explicitly register the default VFS here.
	 * NT_STATUS_OBJECT_NAME_COLLISION (already registered) is fine.
	 */
	vfs_default_init(ctx);

	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "tailscale",
				&vfs_tailscale_fns);
}
