/*
 * Mock tailscaled - a minimal Unix-socket HTTP server that mimics the
 * tailscaled /localapi/v0/whois endpoint for integration testing.
 *
 * Usage: mock_tailscaled <socket_path> <expected_addr> <login_name>
 *
 * Listens on <socket_path>, accepts connections, reads HTTP requests.
 * If the request contains "addr=<expected_addr>", returns a 200 with a
 * valid whois JSON response using <login_name>. Otherwise returns 404.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
	(void)sig;
	running = 0;
}

static void handle_client(int client_fd, const char *expected_addr,
			   const char *login_name)
{
	char reqbuf[4096];
	ssize_t n = read(client_fd, reqbuf, sizeof(reqbuf) - 1);
	if (n <= 0) {
		close(client_fd);
		return;
	}
	reqbuf[n] = '\0';

	fprintf(stderr, "mock_tailscaled: received request: %.200s\n", reqbuf);

	/* Check if the request contains addr=<expected_addr> */
	char needle[256];
	snprintf(needle, sizeof(needle), "addr=%s", expected_addr);

	const char *response;
	char ok_response[1024];

	if (strstr(reqbuf, needle)) {
		snprintf(ok_response, sizeof(ok_response),
			 "HTTP/1.1 200 OK\r\n"
			 "Content-Type: application/json\r\n"
			 "\r\n"
			 "{\"UserProfile\":{\"LoginName\":\"%s\",\"ID\":1}}",
			 login_name);
		response = ok_response;
	} else {
		fprintf(stderr, "mock_tailscaled: expected '%s' in request, "
			"returning 404\n", needle);
		response = "HTTP/1.1 404 Not Found\r\n"
			   "Content-Type: text/plain\r\n"
			   "\r\n"
			   "not found";
	}

	(void)write(client_fd, response, strlen(response));
	close(client_fd);
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr,
			"Usage: %s <socket_path> <expected_addr> <login_name>\n",
			argv[0]);
		return 1;
	}

	const char *socket_path = argv[1];
	const char *expected_addr = argv[2];
	const char *login_name = argv[3];

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	unlink(socket_path);

	int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(listen_fd);
		return 1;
	}

	if (listen(listen_fd, 5) < 0) {
		perror("listen");
		close(listen_fd);
		return 1;
	}

	/* Make socket world-accessible so smbd can connect */
	chmod(socket_path, 0777);

	fprintf(stderr, "mock_tailscaled: listening on %s "
		"(expect addr=%s, login=%s)\n",
		socket_path, expected_addr, login_name);

	/* Notify systemd (type=notify) that we're ready, if sd_notify is
	 * not available just proceed - systemd will use the socket file
	 * appearing as readiness signal via wait_for_file in the test. */

	while (running) {
		int client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd < 0)
			continue;
		handle_client(client_fd, expected_addr, login_name);
	}

	close(listen_fd);
	unlink(socket_path);
	return 0;
}
