#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <curl/curl.h>
#include <jansson.h>

#include "whois.h"

#define MAX_RESPONSE_SIZE (256 * 1024)

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct curl_buf *buf = userdata;
	size_t total = size * nmemb;
	if (size == 0)
		return 0; /* avoid divide-by-zero in the overflow check below */
	if (total / size != nmemb || buf->len + total + 1 < buf->len)
		return 0; /* overflow */
	if (buf->len + total > MAX_RESPONSE_SIZE)
		return 0; /* response too large */
	char *tmp = realloc(buf->data, buf->len + total + 1);
	if (!tmp)
		return 0;
	buf->data = tmp;
	memcpy(buf->data + buf->len, ptr, total);
	buf->len += total;
	buf->data[buf->len] = '\0';
	return total;
}

char *tailscale_whois(const char *ip, const char *socket_path,
		      TALLOC_CTX *mem_ctx)
{
	CURL *curl;
	char url[512];
	struct curl_buf buf = { .data = NULL, .len = 0 };
	char *login_name = NULL;
	long http_code = 0;

	curl = curl_easy_init();
	if (!curl)
		return NULL;

	char *escaped_ip = curl_easy_escape(curl, ip, 0);
	if (!escaped_ip) {
		curl_easy_cleanup(curl);
		return NULL;
	}
	snprintf(url, sizeof(url),
		 "http://local-tailscaled.sock/localapi/v0/whois?addr=%s:0",
		 escaped_ip);
	curl_free(escaped_ip);

	curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket_path);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		goto out;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code != 200 || !buf.data)
		goto out;

	/* Parse JSON: extract UserProfile.LoginName */
	json_error_t jerr;
	json_t *root = json_loads(buf.data, 0, &jerr);
	if (!root)
		goto out;

	json_t *profile = json_object_get(root, "UserProfile");
	if (!profile) {
		json_decref(root);
		goto out;
	}

	json_t *jname = json_object_get(profile, "LoginName");
	if (!jname || !json_is_string(jname)) {
		json_decref(root);
		goto out;
	}

	login_name = talloc_strdup(mem_ctx, json_string_value(jname));
	json_decref(root);

out:
	curl_easy_cleanup(curl);
	free(buf.data);
	return login_name;
}

/*
 * Compare two textual IP addresses for equality, normalizing representation
 * so that e.g. two IPv6 addresses differing only in zero-compression compare
 * equal. Both must parse in the same address family to match.
 */
static bool ip_equal(const char *a, const char *b)
{
	unsigned char ba[16], bb[16];

	if (inet_pton(AF_INET, a, ba) == 1)
		return inet_pton(AF_INET, b, bb) == 1 &&
		       memcmp(ba, bb, 4) == 0;
	if (inet_pton(AF_INET6, a, ba) == 1)
		return inet_pton(AF_INET6, b, bb) == 1 &&
		       memcmp(ba, bb, 16) == 0;
	return false;
}

bool tailscale_local_ip_ok(const char *local_ip, const char *socket_path)
{
	CURL *curl;
	struct curl_buf buf = { .data = NULL, .len = 0 };
	long http_code = 0;
	bool ok = false;

	curl = curl_easy_init();
	if (!curl)
		return false;

	/* peers=false keeps the response small: we only need Self here, and a
	 * full status can exceed MAX_RESPONSE_SIZE on a large tailnet. */
	curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket_path);
	curl_easy_setopt(curl, CURLOPT_URL,
			 "http://local-tailscaled.sock/localapi/v0/status?peers=false");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		goto out;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code != 200 || !buf.data)
		goto out;

	json_error_t jerr;
	json_t *root = json_loads(buf.data, 0, &jerr);
	if (!root)
		goto out;

	/* Prefer Self.TailscaleIPs; fall back to the top-level TailscaleIPs. */
	json_t *self = json_object_get(root, "Self");
	json_t *ips = self ? json_object_get(self, "TailscaleIPs") : NULL;
	if (!json_is_array(ips))
		ips = json_object_get(root, "TailscaleIPs");

	if (json_is_array(ips)) {
		size_t i;
		json_t *val;
		json_array_foreach(ips, i, val) {
			if (json_is_string(val) &&
			    ip_equal(local_ip, json_string_value(val))) {
				ok = true;
				break;
			}
		}
	}

	json_decref(root);

out:
	curl_easy_cleanup(curl);
	free(buf.data);
	return ok;
}
