#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_RESPONSETIMEOUT 10      /* timeout in seconds */
#define MAX_RESPONSESIZ     4000000 /* max download size in bytes */

#ifndef __OpenBSD__
#define pledge(a,b) 0
#endif

/* URI */
struct uri {
	char proto[48];     /* scheme including ":" or "://" */
	char userinfo[256]; /* username [:password] */
	char host[256];
	char port[6];       /* numeric port */
	char path[1024];
	char query[1024];
	char fragment[1024];
};

struct visited {
	int _type;
	char username[1024];
	char path[1024];
	char server[256];
	char port[8];
};

int headerset = 0, isdir = 0;

void
die(int code, const char *fmt, ...)
{
	va_list ap;

	if (!headerset) {
		switch (code) {
		case 400:
			fputs("Status: 400 Bad Request\r\n", stdout);
			break;
		case 403:
			fputs("Status: 403 Permission Denied\r\n", stdout);
			break;
		default:
			fputs("Status: 500 Internal Server Error\r\n", stdout);
			break;
		}
		fputs("Content-Type: text/plain; charset=utf-8\r\n\r\n", stdout);
	}

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	if (isdir)
		fputs("</pre>\n</body>\n</html>\n", stdout);

	exit(1);
}

/* Escape characters below as HTML 2.0 / XML 1.0. */
void
xmlencode(const char *s)
{
	for (; *s; s++) {
		switch(*s) {
		case '<':  fputs("&lt;", stdout);   break;
		case '>':  fputs("&gt;", stdout);   break;
		case '\'': fputs("&#39;", stdout);  break;
		case '&':  fputs("&amp;", stdout);  break;
		case '"':  fputs("&quot;", stdout); break;
		default:   putchar(*s);
		}
	}
}

int
edial(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, save_errno, s;
	const char *cause = NULL;
	struct timeval timeout;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV; /* numeric port only */
	if ((error = getaddrinfo(host, port, &hints, &res0)))
		die(500, "%s: %s: %s:%s\n", __func__, gai_strerror(error), host, port);
	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		           res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		timeout.tv_sec = MAX_RESPONSETIMEOUT;
		timeout.tv_usec = 0;
		if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1)
			die(500, "%s: setsockopt: %s\n", __func__, strerror(errno));

		timeout.tv_sec = MAX_RESPONSETIMEOUT;
		timeout.tv_usec = 0;
		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
			die(500, "%s: setsockopt: %s\n", __func__, strerror(errno));

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}
		break;
	}
	if (s == -1)
		die(500, "%s: %s: %s:%s\n", __func__, cause, host, port);
	freeaddrinfo(res0);

	return s;
}

int
isblacklisted(const char *host, const char *port, const char *path)
{
	char *p;

	if (strcmp(port, "70") && strcmp(port, "7070"))
		return 1;
	if ((p = strstr(host, ".onion")) && strlen(p) == strlen(".onion"))
		return 1;
	return 0;
}

char *
typestr(int c)
{
	switch (c) {
	case '0': return "  TEXT";
	case '1': return "   DIR";
	case '2': return "   CSO";
	case '3': return "   ERR";
	case '4': return "   MAC";
	case '5': return "   DOS";
	case '6': return " UUENC";
	case '7': return "SEARCH";
	case '8': return "TELNET";
	case '9': return "   BIN";
	case 'g': return "   GIF";
	case 'h': return "  HTML"; /* non-standard */
	case 's': return "   SND"; /* non-standard */
	case '+': return "MIRROR";
	case 'I': return "   IMG";
	case 'T': return "TN3270";
	default:
		/* "Characters '0' through 'Z' are reserved." (ASCII) */
		if (c >= '0' && c <= 'Z')
			return "RESERV";
		else
			return "      ";
	}
}

void
servefile(const char *server, const char *port, const char *path)
{
	char buf[1024];
	int r, w, fd;
	size_t totalsiz = 0;

	fd = edial(server, port);

	if (pledge("stdio", NULL) == -1)
		die(500, "pledge: %s\n", strerror(errno));

	if ((w = dprintf(fd, "%s\r\n", path)) == -1)
		die(500, "dprintf: %s\n", strerror(errno));

	while ((r = read(fd, buf, sizeof(buf))) > 0) {
		/* too big total response */
		totalsiz += r;
		if (totalsiz > MAX_RESPONSESIZ) {
			dprintf(1, "--- transfer too big, truncated ---\n");
			break;
		}

		if ((w = write(1, buf, r)) == -1)
			die(500, "write: %s\n", strerror(errno));
	}
	if (r == -1)
		die(500, "read: %s\n", strerror(errno));
	close(fd);
}

void
servedir(const char *server, const char *port, const char *path, const char *param)
{
	struct visited v;
	FILE *fp;
	char line[1024], uri[1024], primarytype;
	size_t totalsiz, linenr;
	ssize_t n;
	int fd, r, i, len;

	fd = edial(server, port);

	if (pledge("stdio", NULL) == -1)
		die(500, "pledge: %s\n", strerror(errno));

	if (param[0])
		r = dprintf(fd, "%s\t%s\r\n", path, param);
	else
		r = dprintf(fd, "%s\r\n", path);
	if (r == -1)
		die(500, "write: %s\n", strerror(errno));

	if (!(fp = fdopen(fd, "rb+")))
		die(500, "fdopen: %s\n", strerror(errno));

	totalsiz = 0;
	primarytype = '\0';
	for (linenr = 1; fgets(line, sizeof(line), fp); linenr++) {
		n = strcspn(line, "\n");
		if (line[n] != '\n')
			die(500, "%s:%s %s:%d: line too long\n",
				server, port, path, linenr);
		if (n && line[n] == '\n')
			line[n] = '\0';
		if (n && line[n - 1] == '\r')
			line[--n] = '\0';
		if (n == 1 && line[0] == '.')
			break;

		/* too big total response */
		totalsiz += n;
		if (totalsiz > MAX_RESPONSESIZ) {
			dprintf(1, "--- transfer too big, truncated ---\n");
			break;
		}

		memset(&v, 0, sizeof(v));

		v._type = line[0];
		if (v._type != '+')
			primarytype = v._type;
		else if (!primarytype)
			die(500, "%s:%s %s:%d: undefined primary server\n",
				server, port, path, linenr);

		/* "username" */
		i = 1;
		len = strcspn(line + i, "\t");
		if (len + 1 < sizeof(v.username)) {
			memcpy(v.username, line + i, len);
			v.username[len] = '\0';
		} else  {
			die(500, "%s:%s %s:%d: username field too long\n",
				server, port, path, linenr);
		}
		if (line[i + len] == '\t')
			i += len + 1;
		else
			die(500, "%s:%s %s:%d: invalid line / field count\n",
				server, port, path, linenr);

		/* selector / path */
		len = strcspn(line + i, "\t");
		if (len + 1 < sizeof(v.path)) {
			memcpy(v.path, line + i, len);
			v.path[len] = '\0';
		} else {
			die(500, "%s:%s %s:%d: path field too long\n",
				server, port, path, linenr);
		}
		if (line[i + len] == '\t')
			i += len + 1;
		else
			die(500, "%s:%s %s:%d: invalid line / field count\n",
				server, port, path, linenr);

		/* server */
		len = strcspn(line + i, "\t");
		if (len + 1 < sizeof(v.server)) {
			memcpy(v.server, line + i, len);
			v.server[len] = '\0';
		} else {
			die(500, "%s:%s %s:%d: server field too long\n",
				server, port, path, linenr);
		}
		if (line[i + len] == '\t')
			i += len + 1;
		else
			die(500, "%s:%s %s:%d: invalid line / field count\n",
				server, port, path, linenr);

		/* port */
		len = strcspn(line + i, "\t");
		if (len + 1 < sizeof(v.port)) {
			memcpy(v.port, line + i, len);
			v.port[len] = '\0';
		} else {
			die(500, "%s:%s %s:%d: port field too long\n",
				server, port, path, linenr);
		}

		if (!strcmp(v.port, "70"))
			snprintf(uri, sizeof(uri), "%s/%c%s",
				v.server, primarytype, v.path);
		else
			snprintf(uri, sizeof(uri), "%s:%s/%c%s",
				v.server, v.port, primarytype, v.path);

		switch (primarytype) {
		case 'i': /* info */
		case '3': /* error */
			fputs(typestr(v._type), stdout);
			fputs(" ", stdout);
			xmlencode(v.username);
			break;
		case '7': /* search */
			fputs("</pre><form method=\"get\" action=\"\"><pre>", stdout);
			fputs(typestr(v._type), stdout);
			fputs(" <input type=\"hidden\" name=\"q\" value=\"", stdout);
			xmlencode(uri);
			fputs("\" /><input type=\"search\" placeholder=\"", stdout);
			xmlencode(v.username);
			fputs(
				"\" name=\"p\" value=\"\" size=\"72\" />"
				"<input type=\"submit\" value=\"Search\" /></pre></form><pre>", stdout);
			break;
		case '8': /* telnet */
		case 'T': /* tn3270 */
			fputs(typestr(v._type), stdout);
			printf(" <a href=\"%s://", primarytype == '8' ? "telnet" : "tn3270");
			if (v.path[0]) {
				xmlencode(v.path);
				fputs("@", stdout);
			}
			xmlencode(v.server);
			fputs(":", stdout);
			xmlencode(v.port);
			fputs("\">", stdout);
			xmlencode(v.username);
			fputs("</a>", stdout);
			break;
		default: /* other */
			fputs(typestr(v._type), stdout);
			fputs(" <a href=\"", stdout);
			if (primarytype == 'h' && !strncmp(v.path, "URL:", sizeof("URL:") - 1)) {
				xmlencode(v.path + sizeof("URL:") - 1);
			} else {
				fputs("?q=", stdout);
				xmlencode(uri);
			}
			fputs("\">", stdout);
			xmlencode(v.username);
			fputs("</a>", stdout);

		}
		putchar('\n');
	}
	if (ferror(fp))
		die(500, "fgets: %s\n", strerror(errno));
	fclose(fp);
}

int
hexdigit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	return 0;
}

/* decode until NUL separator or end of "key". */
int
decodeparam(char *buf, size_t bufsiz, const char *s)
{
	size_t i;

	if (!bufsiz)
		return -1;

	for (i = 0; *s && *s != '&'; s++) {
		if (i + 3 >= bufsiz)
			return -1;
		switch (*s) {
		case '%':
			if (!isxdigit(*(s+1)) || !isxdigit(*(s+2)))
				return -1;
			buf[i++] = hexdigit(*(s+1)) * 16 + hexdigit(*(s+2));
			s += 2;
			break;
		case '+':
			buf[i++] = ' ';
			break;
		default:
			buf[i++] = *s;
			break;
		}
	}
	buf[i] = '\0';

	return i;
}

char *
getparam(const char *query, const char *s)
{
	const char *p;
	size_t len;

	len = strlen(s);
	for (p = query; (p = strstr(p, s)); p += len) {
		if (p[len] == '=' && (p == query || p[-1] == '&'))
			return (char *)p + len + 1;
	}

	return NULL;
}

int
checkparam(const char *s)
{
	for (; *s; s++)
		if (iscntrl(*s))
			return 0;
	return 1;
}

/* Check if string has a non-empty scheme / protocol part. */
int
uri_hasscheme(const char *s)
{
	const char *p = s;

	for (; isalpha((unsigned char)*p) || isdigit((unsigned char)*p) ||
		       *p == '+' || *p == '-' || *p == '.'; p++)
		;
	/* scheme, except if empty and starts with ":" then it is a path */
	return (*p == ':' && p != s);
}

/* Parse URI string `s` into an uri structure `u`.
   Returns 0 on success or -1 on failure */
int
uri_parse(const char *s, struct uri *u)
{
	const char *p = s;
	char *endptr;
	size_t i;
	long l;

	u->proto[0] = u->userinfo[0] = u->host[0] = u->port[0] = '\0';
	u->path[0] = u->query[0] = u->fragment[0] = '\0';

	/* protocol-relative */
	if (*p == '/' && *(p + 1) == '/') {
		p += 2; /* skip "//" */
		goto parseauth;
	}

	/* scheme / protocol part */
	for (; isalpha((unsigned char)*p) || isdigit((unsigned char)*p) ||
		       *p == '+' || *p == '-' || *p == '.'; p++)
		;
	/* scheme, except if empty and starts with ":" then it is a path */
	if (*p == ':' && p != s) {
		if (*(p + 1) == '/' && *(p + 2) == '/')
			p += 3; /* skip "://" */
		else
			p++; /* skip ":" */

		if ((size_t)(p - s) >= sizeof(u->proto))
			return -1; /* protocol too long */
		memcpy(u->proto, s, p - s);
		u->proto[p - s] = '\0';

		if (*(p - 1) != '/')
			goto parsepath;
	} else {
		p = s; /* no scheme format, reset to start */
		goto parsepath;
	}

parseauth:
	/* userinfo (username:password) */
	i = strcspn(p, "@/?#");
	if (p[i] == '@') {
		if (i >= sizeof(u->userinfo))
			return -1; /* userinfo too long */
		memcpy(u->userinfo, p, i);
		u->userinfo[i] = '\0';
		p += i + 1;
	}

	/* IPv6 address */
	if (*p == '[') {
		/* bracket not found, host too short or too long */
		i = strcspn(p, "]");
		if (p[i] != ']' || i < 3)
			return -1;
		i++; /* including "]" */
	} else {
		/* domain / host part, skip until port, path or end. */
		i = strcspn(p, ":/?#");
	}
	if (i >= sizeof(u->host))
		return -1; /* host too long */
	memcpy(u->host, p, i);
	u->host[i] = '\0';
	p += i;

	/* port */
	if (*p == ':') {
		p++;
		if ((i = strcspn(p, "/?#")) >= sizeof(u->port))
			return -1; /* port too long */
		memcpy(u->port, p, i);
		u->port[i] = '\0';
		/* check for valid port: range 1 - 65535, may be empty */
		errno = 0;
		l = strtol(u->port, &endptr, 10);
		if (i && (errno || *endptr || l <= 0 || l > 65535))
			return -1;
		p += i;
	}

parsepath:
	/* path */
	if ((i = strcspn(p, "?#")) >= sizeof(u->path))
		return -1; /* path too long */
	memcpy(u->path, p, i);
	u->path[i] = '\0';
	p += i;

	/* query */
	if (*p == '?') {
		p++;
		if ((i = strcspn(p, "#")) >= sizeof(u->query))
			return -1; /* query too long */
		memcpy(u->query, p, i);
		u->query[i] = '\0';
		p += i;
	}

	/* fragment */
	if (*p == '#') {
		p++;
		if ((i = strlen(p)) >= sizeof(u->fragment))
			return -1; /* fragment too long */
		memcpy(u->fragment, p, i);
		u->fragment[i] = '\0';
	}

	return 0;
}

int
main(void)
{
	struct uri u;
	const char *p, *qs, *path, *showuri = "";
	char query[1024] = "", param[1024] = "", fulluri[4096];
	int r, _type = '1';

	if (pledge("stdio inet dns", NULL) == -1)
		die(500, "pledge: %s\n", strerror(errno));

	if (!(qs = getenv("QUERY_STRING")))
		qs = "";
	if ((p = getparam(qs, "q"))) {
		if (decodeparam(query, sizeof(query), p) == -1 ||
		    !checkparam(query))
			die(400, "Invalid parameter: q\n");
	}
	if ((p = getparam(qs, "p"))) {
		if (decodeparam(param, sizeof(param), p) == -1 ||
		    !checkparam(param))
			die(400, "Invalid parameter: p\n");
	}

	path = "/";
	if (query[0]) {
		if (!strncmp(query, "gopher://", sizeof("gopher://") - 1)) {
			showuri = query + sizeof("gopher://") - 1;
			r = snprintf(fulluri, sizeof(fulluri), "%s", query);
		} else {
			showuri = query;
			if (uri_hasscheme(query))
				die(400, "Invalid protocol: only gopher is supported\n");
			r = snprintf(fulluri, sizeof(fulluri), "gopher://%s", query);
		}
		if (r < 0 || (size_t)r >= sizeof(fulluri))
			die(400, "invalid URI: too long\n");

		if (!uri_hasscheme(fulluri) ||
		    uri_parse(fulluri, &u) == -1)
			die(400, "Invalid or unsupported URI: %s\n", showuri);

		if (strcmp(u.proto, "gopher://"))
			die(400, "Invalid protocol: only gopher is supported\n");
		if (u.host[0] == '\0')
			die(400, "Invalid hostname\n");

		if (u.path[0] == '\0')
			memcpy(u.path, "/", 2);
		if (u.port[0] == '\0')
			memcpy(u.port, "70", 3);

		path = u.path;
		if (path[0] == '/') {
			path++;
			if (*path) {
				_type = *path;
				path++;
			}
		} else {
			path = "";
		}

		if (isblacklisted(u.host, u.port, path))
			die(403, "%s:%s %s: blacklisted\n", u.host, u.port, path);

		headerset = 1;
		switch (_type) {
		case '1':
		case '7':
			break; /* handled below */
		case '0':
			dprintf(1, "Content-Type: text/plain; charset=utf-8\r\n\r\n");
			servefile(u.host, u.port, path);
			return 0;
		case 'g':
			dprintf(1, "Content-Type: image/gif\r\n\r\n");
			servefile(u.host, u.port, path);
			return 0;
		case 'I':
			/* try to set Content-Type based on extension */
			if ((p = strrchr(path, '.'))) {
				p++;
				if (!strcasecmp("png", p))
					dprintf(1, "Content-Type: image/png\r\n");
				else if (!strcasecmp("jpg", p) || !strcasecmp("jpeg", p))
					dprintf(1, "Content-Type: image/jpeg\r\n");
				else if (!strcasecmp("gif", p))
					dprintf(1, "Content-Type: image/gif\r\n");
			}
			write(1, "\r\n", 2);
			servefile(u.host, u.port, path);
			return 0;
		case '9':
			/* try to detect filename */
			if ((p = strrchr(path, '/')))
				dprintf(1, "Content-Disposition: attachment; filename=\"%s\"\r\n", p + 1);
			dprintf(1, "Content-Type: application/octet-stream\r\n\r\n");
			servefile(u.host, u.port, path);
			return 0;
		default:
			write(1, "\r\n", 2);
			servefile(u.host, u.port, path);
			return 0;
		}
	}

	headerset = isdir = 1;
	fputs(
		"Content-Type: text/html; charset=utf-8\r\n"
		"\r\n"
		"<!DOCTYPE html>\n"
		"<html dir=\"ltr\">\n"
		"<head>\n"
		"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
		"<title>", stdout);
	xmlencode(query);
	if (query[0])
		fputs(" - ", stdout);
	fputs(
		"Gopher HTTP proxy</title>\n"
		"<style type=\"text/css\">\n"
		"a { text-decoration: none; } a:hover { text-decoration: underline; }\n"
		"@media (prefers-color-scheme: dark) { body { background-color: #000; color: #bdbdbd; } a { color: #56c8ff; } input { border: 1px solid #777; color: #cdcdcd; background-color: #333 } }\n"
		"</style>\n"
		"<meta name=\"robots\" content=\"noindex, nofollow\" />\n"
		"<meta name=\"robots\" content=\"none\" />\n"
		"<meta content=\"width=device-width\" name=\"viewport\" />\n"
		"</head>\n"
		"<body>\n"
		"<form method=\"get\" action=\"\"><pre>"
		"  URI: <input type=\"search\" name=\"q\" value=\"", stdout);
	xmlencode(showuri);
	fputs(
		"\" placeholder=\"URI...\" size=\"72\" autofocus=\"autofocus\" class=\"search\" />"
		"<input type=\"submit\" value=\"Go for it!\" /></pre>"
		"</form><pre>\n", stdout);

	if (query[0]) {
		if (_type != '7')
			param[0] = '\0';
		servedir(u.host, u.port, path, param);
	}

	fputs("</pre>\n</body>\n</html>\n", stdout);

	return 0;
}
