#ifndef WHOIS_H
#define WHOIS_H

#include <stddef.h>
#include <talloc.h>

struct curl_buf {
	char *data;
	size_t len;
};

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata);

char *tailscale_whois(const char *ip, const char *socket_path,
		      TALLOC_CTX *mem_ctx);

#endif
