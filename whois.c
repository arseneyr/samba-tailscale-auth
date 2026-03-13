#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>
#include <jansson.h>

#include "whois.h"

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct curl_buf *buf = userdata;
	size_t total = size * nmemb;
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

	snprintf(url, sizeof(url),
		 "http://local-tailscaled.sock/localapi/v0/whois?addr=%s:0",
		 ip);

	curl = curl_easy_init();
	if (!curl)
		return NULL;

	curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket_path);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		goto out;

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
	if (http_code != 200)
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
