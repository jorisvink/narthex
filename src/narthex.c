/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/hooks.h>

void		usage(void) __attribute__((noreturn));

int		narthex_register(struct http_request *);
void		narthex_set_options(int, const char *, const char *);

void
usage(void)
{
	fprintf(stderr, "Usage: narthex [options]\n");
	fprintf(stderr, "available options:\n");
	fprintf(stderr, "  -c    - path to the certificate\n");
	fprintf(stderr, "  -d    - the domain name to serve under\n");
	fprintf(stderr, "  -k    - path to the private key\n");
	fprintf(stderr, "  -i    - optional ip address to bind on\n");
	fprintf(stderr, "  -p    - optional port to bind on\n");
	fprintf(stderr, "  -r    - the worker root directory\n");
	fprintf(stderr, "  -u    - the worker runas user\n");

	exit(1);
}

void
kore_parent_configure(int argc, char *argv[])
{
	struct kore_route	*rt;
	struct kore_server	*srv;
	struct kore_domain	*dom;
	int			ch, foreground;
	const char		*runas, *rootdir;
	const char		*certfile, *domain, *keyfile, *ip, *port;

	domain = NULL;
	keyfile = NULL;
	certfile = NULL;

	runas = NULL;
	rootdir = NULL;

	port = "8192";
	ip = "0.0.0.0";
	foreground = 0;

	while ((ch = getopt(argc, argv, "c:d:fk:i:p:r:u:")) != -1) {
		switch (ch) {
		case 'c':
			certfile = optarg;
			break;
		case 'd':
			domain = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'i':
			ip = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'r':
			rootdir = optarg;
			break;
		case 'u':
			runas = optarg;
			break;
		default:
			usage();
		}
	}

	if (certfile == NULL || domain == NULL ||
	    keyfile == NULL || rootdir == NULL)
		usage();

	narthex_set_options(foreground, runas, rootdir);

	srv = kore_server_create("default");
	if (!kore_server_bind(srv, ip, port, NULL))
		fatal("failed to create listener");

	dom = kore_domain_new(domain);
	dom->certkey = kore_strdup(keyfile);
	dom->certfile = kore_strdup(certfile);

	rt = kore_route_create(dom,
	    "^/register/0x[a-f0-9]{2,8}$", HANDLER_TYPE_DYNAMIC);

	rt->methods = HTTP_METHOD_PUT;
	kore_route_callback(rt, "narthex_register");

	kore_domain_attach(dom, srv);
	kore_server_finalize(srv);
}

void
narthex_set_options(int foreground, const char *runas, const char *rootdir)
{
	skip_runas = 1;
	worker_count = 1;
	kore_foreground = foreground;

	http_keepalive_time = 0;
	http_server_version("narthex");

	http_body_max = 32;
	http_body_disk_offload = 0;

	keymgr_privsep.skip_runas = 1;
	keymgr_privsep.skip_chroot = 1;

	worker_privsep.root = kore_strdup(rootdir);

	if (runas == NULL)
		worker_privsep.skip_runas = 1;
	else
		worker_privsep.runas = kore_strdup(runas);
}

int
narthex_register(struct http_request *req)
{
	const char		*id;
	ssize_t			ret;
	u_int32_t		keyid;
	int			err, fd, len;
	char			path[PATH_MAX];

	if (req->method != HTTP_METHOD_PUT)
		return (KORE_RESULT_ERROR);

	if ((id = strrchr(req->path, '/')) == NULL)
		return (KORE_RESULT_ERROR);

	keyid = kore_strtonum(id + 1, 16, 0, UINT_MAX, &err);
	if (err != KORE_RESULT_OK) {
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return (KORE_RESULT_OK);
	}

	len = snprintf(path, sizeof(path), "0x%x.key", keyid);
	if (len == -1 || (size_t)len >= sizeof(path)) {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (KORE_RESULT_OK);
	}

	fd = open(path, O_CREAT | O_TRUNC | O_EXCL | O_WRONLY, 0700);
	if (fd == -1) {
		if (errno == EEXIST) {
			http_response(req, HTTP_STATUS_CONFLICT, NULL, 0);
		} else {
			kore_log(LOG_NOTICE,
			    "failed to open %s (%s)", path, errno_s);
			http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		}
		return (KORE_RESULT_OK);
	}

	ret = write(fd, req->http_body->data, req->http_body->length);
	if (ret == -1 || (size_t)ret != req->http_body->length) {
		kore_log(LOG_NOTICE, "failed to write keyfile %s", path);
		(void)close(fd);
		(void)unlink(path);
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return (KORE_RESULT_OK);
	}

	if (close(fd) == -1)
		kore_log(LOG_NOTICE, "%s failed to close (%s)", path, errno_s);

	http_response(req, HTTP_STATUS_CREATED, NULL, 0);

	return (KORE_RESULT_OK);
}
