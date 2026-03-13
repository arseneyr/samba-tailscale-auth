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
#include <errno.h>
#include <syslog.h>
#include <talloc.h>

#include "whois.h"

/* Samba public header for NTSTATUS */
#define HAVE_IMMEDIATE_STRUCTURES 1
#include <core/ntstatus.h>

/*
 * Vendored private struct declarations from samba 4.22.6
 * (source3/include/vfs.h, source3/smbd/globals.h).
 *
 * Only fields up to the ones we access are defined.  We never allocate
 * these structs — we only chase pointers into smbd's existing copies.
 */

#define SMB_VFS_INTERFACE_VERSION 50

/* Opaque types we only use as pointers */
struct tsocket_address;
struct auth_session_info;
struct smbXsrv_tcon;
struct share_params;
struct vuid_cache;
struct files_struct;
struct vfs_handle_struct;

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

#define DEFAULT_TAILSCALE_SOCKET "/var/run/tailscale/tailscaled.sock"

/* --- VFS connect implementation --- */

static int tailscale_connect(vfs_handle_struct *handle,
			     const char *service, const char *user)
{
	connection_struct *conn = handle->conn;
	const char *ip;
	const char *socket_path;
	char *login_name;
	struct auth_session_info *new_session_info = NULL;
	NTSTATUS status;
	int ret;

	/* Chain to the default VFS first */
	ret = smb_vfs_call_connect(handle->next, service, user);
	if (ret < 0)
		return ret;

	/* Get client IP */
	ip = tsocket_address_inet_addr_string(conn->sconn->remote_address,
					      conn);
	if (!ip) {
		syslog(LOG_ERR, "vfs_tailscale: failed to get client IP");
		errno = EACCES;
		return -1;
	}

	/* Socket path from module parameter, or default */
	socket_path = handle->param;
	if (!socket_path || !*socket_path)
		socket_path = DEFAULT_TAILSCALE_SOCKET;

	/* Query tailscaled for the identity of this peer */
	login_name = tailscale_whois(ip, socket_path, conn);
	if (!login_name) {
		syslog(LOG_WARNING,
		       "vfs_tailscale: denying %s — not a tailscale peer", ip);
		errno = EACCES;
		return -1;
	}

	syslog(LOG_INFO, "vfs_tailscale: %s -> %s", ip, login_name);

	/* Build a new session_info for the mapped user */
	status = make_session_info_from_username(conn, login_name, false,
						 &new_session_info);
	if (!NT_STATUS_IS_OK(status)) {
		syslog(LOG_ERR,
		       "vfs_tailscale: make_session_info_from_username(%s) failed",
		       login_name);
		errno = EPERM;
		return -1;
	}

	/* Replace the guest session with the real user */
	talloc_free(conn->session_info);
	conn->session_info = new_session_info;
	conn->force_user = true;

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
