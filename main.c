/*
	RFC1459
	http://tools.ietf.org/html/rfc1459

	RFC2812
	https://tools.ietf.org/html/rfc2812

	irc commands
	https://www.alien.net.au/irc/irc2numerics.html
*/

#pragma comment(linker, "/OPT:NOWIN98")
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

BOOL shutdown_;

void send_msg(SOCKET s, const char *fmt, ...) {
	char a[1024];
	int n = _vsnprintf(a, sizeof(a), fmt, (char *)&fmt + sizeof(void *));
	if (n) {
		if (n < 0 || n > 510) {
			printf("send_msg: message overflow (limit to 510 bytes)\n");
			n = 510;
		}
		*(short *)&a[n] = 0x0a0d;
		send(s, a, n + 2, 0);
	}
}

void parse_msg(SOCKET s, char *p) {
	unsigned i;
	struct {
		char *nick, *user, *host, *cmd;
		unsigned args;
		char *arg[16];
	} msg;

	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		printf("%02u:%02u:%02u.%03u %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, p);
	}

	ZeroMemory(&msg, sizeof(msg));

	if (*p == ':') {
		for (msg.nick = ++p; *p && *p != ' '; ++p)
			if (*p == '!') {
				for (msg.user = (*p = 0, ++p); *p && *p != ' '; ++p)
					if (*p == '@') {
						msg.host = (*p = 0, ++p);
						break;
					}
				break;
			}
		if (!(p = strchr(p, ' ')))
			return;
		*p++ = 0;
	}

	msg.cmd = p;

	if (p = strchr(p, ' ')) {
		*p++ = 0;
		if (*p == ':')
			msg.args = 1, *msg.arg = &p[1];
		else
			for (msg.args = 1, *msg.arg = p; p = strchr(p, ' ');) {
				if (p[1] == ':') {
					msg.arg[msg.args++] = (*p = 0, &p[2]);
					break;
				}
				msg.arg[msg.args++] = (*p = 0, ++p);
				if (msg.args == sizeof(msg.arg) / sizeof(*msg.arg))
					break;
			}
	}

	printf("[%s][%s][%s][%s]\n",
		msg.nick,
		msg.user,
		msg.host,
		msg.cmd);

	for (i = 0; i < msg.args; ++i)
		printf("%d = %s\n", i, msg.arg[i]);

	printf("\n");

	if (*msg.cmd < '0' || *msg.cmd > '9')
		switch (*msg.cmd) {
		case 'K':
			if (!strcmp(msg.cmd, "KICK")) {
				if (!strcmp(*msg.arg, "#anzu"))
					send_msg(s, "join #anzu ^0^");
			}
			break;
		case 'P':
			if (!strcmp(msg.cmd, "PING"))
				send_msg(s, "PONG :%s", *msg.arg);
			else if (!strcmp(msg.cmd, "PRIVMSG")) {
				// *msg.arg start with # -> channel message
				// others -> private message
			}
			break;
		}
	else
		switch (atoi(msg.cmd)) {
		case 4: // RPL_MYINFO
			send_msg(s, "join #anzu ^0^");
			break;

		case 432: // ERR_ERRONEUSNICKNAME
			send_msg(s, "NICK a%s", *msg.arg);
			break;

		case 433: // ERR_NICKNAMEINUSE
			send_msg(s, "NICK a%s", *msg.arg);
			break;

		case 461: // ERR_NEEDMOREPARAMS
			if (!strcmp(msg.arg[1], "NICK"))
				send_msg(s, "NICK a%s", *msg.arg);
			break;
		}
}

SOCKET make_connect(const char *host, int port) {
	struct sockaddr_in a;
	struct hostent *h;
	u_long u;
	ZeroMemory(&a, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_port = htons((u_short)port);
	if ((u = inet_addr(host)) == INADDR_NONE &&
		(h = gethostbyname(host)))
		u = *(u_long *)h->h_addr;
	a.sin_addr.s_addr = u;
	if (u != INADDR_NONE) {
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (u = 1u, (char *)&u), sizeof(u));
		if (!connect(s, (struct sockaddr *)&a, sizeof(a)))
			return s;
		closesocket(s);
	}
	return INVALID_SOCKET;
}

int main(int argc, char **argv) {
	char a[16384];
	if (!WSAStartup(0x202u, (WSADATA *)a)) {
		do {
			SOCKET s = make_connect("8080.luatic.net", 8080);
			if (s != INVALID_SOCKET) {
				int n = 0;
				send_msg(s, "USER anzu 8 * :");
				send_msg(s, "NICK *");
				for (;;) {
					int p, i = recv(s, &a[n], sizeof(a) - n, 0);
					if (i <= 0)
						break;
					for (n += i, p = i = 0; i + 2 <= n;)
						if (*(short *)&a[i] == 0x0a0d) {
							*(short *)&a[i] = 0;
							parse_msg(s, &a[p]);
							p = i += 2;
						} else
							++i;
					if (p)
						memcpy(a, &a[p], n -= p);
				}
				shutdown(s, SD_BOTH);
				closesocket(s);
			}
			printf("connection has gone\n");
			Sleep(10000);
		} while (!shutdown_);
		WSACleanup();
	}
	return 0;
}