#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <talloc.h>

#include "whois.h"

#define ASSERT(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s\n  %s:%d\n", msg, __FILE__, __LINE__); \
		exit(1); \
	} \
} while (0)

struct mock_server {
	char socket_path[128];
	int listen_fd;
	const char *response;
};

static void mock_server_init(struct mock_server *srv, const char *response)
{
	srv->response = response;

	snprintf(srv->socket_path, sizeof(srv->socket_path),
		 "/tmp/test_whois_%d.sock", getpid());
	unlink(srv->socket_path);

	srv->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(srv->listen_fd >= 0, "socket() failed");

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, srv->socket_path, sizeof(addr.sun_path) - 1);

	ASSERT(bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0,
	       "bind() failed");
	ASSERT(listen(srv->listen_fd, 1) == 0, "listen() failed");
}

static void mock_server_cleanup(struct mock_server *srv)
{
	close(srv->listen_fd);
	unlink(srv->socket_path);
}

static void *mock_server_thread(void *arg)
{
	struct mock_server *srv = arg;
	int client_fd = accept(srv->listen_fd, NULL, NULL);
	if (client_fd < 0)
		return NULL;

	/* Read the HTTP request (we don't parse it, just drain it) */
	char reqbuf[4096];
	read(client_fd, reqbuf, sizeof(reqbuf));

	/* Send the canned HTTP response */
	write(client_fd, srv->response, strlen(srv->response));
	close(client_fd);
	return NULL;
}

static void test_happy_path(void)
{
	const char *response =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"\r\n"
		"{\"UserProfile\":{\"LoginName\":\"user@example.com\",\"ID\":12345}}";

	struct mock_server srv;
	mock_server_init(&srv, response);

	pthread_t tid;
	pthread_create(&tid, NULL, mock_server_thread, &srv);

	TALLOC_CTX *ctx = talloc_new(NULL);
	char *result = tailscale_whois("100.64.1.1", srv.socket_path, ctx);

	pthread_join(tid, NULL);
	mock_server_cleanup(&srv);

	ASSERT(result != NULL, "expected non-NULL login name");
	ASSERT(strcmp(result, "user@example.com") == 0,
	       "expected user@example.com");

	talloc_free(ctx);
	printf("  PASS: happy path\n");
}

static void test_missing_user_profile(void)
{
	const char *response =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"\r\n"
		"{\"Node\":{\"ID\":1}}";

	struct mock_server srv;
	mock_server_init(&srv, response);

	pthread_t tid;
	pthread_create(&tid, NULL, mock_server_thread, &srv);

	TALLOC_CTX *ctx = talloc_new(NULL);
	char *result = tailscale_whois("100.64.1.2", srv.socket_path, ctx);

	pthread_join(tid, NULL);
	mock_server_cleanup(&srv);

	ASSERT(result == NULL, "expected NULL when UserProfile missing");

	talloc_free(ctx);
	printf("  PASS: missing UserProfile\n");
}

static void test_missing_login_name(void)
{
	const char *response =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"\r\n"
		"{\"UserProfile\":{\"DisplayName\":\"Some User\"}}";

	struct mock_server srv;
	mock_server_init(&srv, response);

	pthread_t tid;
	pthread_create(&tid, NULL, mock_server_thread, &srv);

	TALLOC_CTX *ctx = talloc_new(NULL);
	char *result = tailscale_whois("100.64.1.3", srv.socket_path, ctx);

	pthread_join(tid, NULL);
	mock_server_cleanup(&srv);

	ASSERT(result == NULL, "expected NULL when LoginName missing");

	talloc_free(ctx);
	printf("  PASS: missing LoginName\n");
}

static void test_http_404(void)
{
	const char *response =
		"HTTP/1.1 404 Not Found\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"not found";

	struct mock_server srv;
	mock_server_init(&srv, response);

	pthread_t tid;
	pthread_create(&tid, NULL, mock_server_thread, &srv);

	TALLOC_CTX *ctx = talloc_new(NULL);
	char *result = tailscale_whois("100.64.1.4", srv.socket_path, ctx);

	pthread_join(tid, NULL);
	mock_server_cleanup(&srv);

	ASSERT(result == NULL, "expected NULL on HTTP 404");

	talloc_free(ctx);
	printf("  PASS: HTTP 404\n");
}

static void test_connection_failure(void)
{
	TALLOC_CTX *ctx = talloc_new(NULL);
	char *result = tailscale_whois("100.64.1.5",
				       "/tmp/nonexistent_socket.sock", ctx);

	ASSERT(result == NULL, "expected NULL on connection failure");

	talloc_free(ctx);
	printf("  PASS: connection failure\n");
}

int main(void)
{
	printf("test_whois:\n");
	test_happy_path();
	test_missing_user_profile();
	test_missing_login_name();
	test_http_404();
	test_connection_failure();
	printf("All tests passed.\n");
	return 0;
}
