#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Build with:
 *   cc -O2 -Wall -Wextra \
 *     -DEXPECTED_UID="$(id -u)" \
 *     -DEGRESS_GID=62001 \
 *     -DPROXY_PORT=17891 \
 *     -o claude_egress_gid_launcher \
 *     claude_egress_gid_launcher.c
 *
 * Install root-owned and setgid:
 *   sudo chown root:<gid-name> claude_egress_gid_launcher
 *   sudo chmod 2755 claude_egress_gid_launcher
 *
 * This launcher changes only process identity and environment. It never
 * changes system routes, PF, PAC or VPN state.
 */

#ifndef EXPECTED_UID
#error "Compile with -DEXPECTED_UID=$(id -u)"
#endif

#ifndef EGRESS_GID
#define EGRESS_GID 62001
#endif

#ifndef PROXY_PORT
#define PROXY_PORT 17891
#endif

extern char **environ;

static int execute(const char *program, char *const arguments[]) {
  execve(program, arguments, environ);
  perror("execve");
  return 113;
}

int main(int argc, char *argv[]) {
  char proxy[64];

  if (getuid() != EXPECTED_UID || geteuid() != EXPECTED_UID ||
      getegid() != EGRESS_GID) {
    fputs("CLAUDE_EGRESS_GROUP_IDENTITY_MISMATCH\n", stderr);
    return 111;
  }

  if (setregid(EGRESS_GID, EGRESS_GID) != 0 ||
      getgid() != EGRESS_GID || getegid() != EGRESS_GID) {
    perror("CLAUDE_EGRESS_PERMANENT_GID_REQUIRED");
    return 116;
  }

  snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%d", PROXY_PORT);
  if (setenv("HTTPS_PROXY", proxy, 1) ||
      setenv("HTTP_PROXY", proxy, 1) ||
      setenv("https_proxy", proxy, 1) ||
      setenv("http_proxy", proxy, 1) ||
      setenv("ALL_PROXY", proxy, 1) ||
      setenv("all_proxy", proxy, 1)) {
    perror("CLAUDE_EGRESS_PROXY_ENV_FAILED");
    return 115;
  }

  if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
    printf("CLAUDE_EGRESS_GID_READY=%ld REAL_GID=%ld UID=%ld\n",
           (long)getegid(), (long)getgid(), (long)geteuid());
    return 0;
  }

  if (argc == 3 && strcmp(argv[1], "--probe") == 0) {
    char port[16];
    snprintf(port, sizeof(port), "%d", PROXY_PORT);
    if (strcmp(argv[2], "direct") == 0) {
      char *args[] = {"/usr/bin/nc", "-G", "4", "-z", "1.1.1.1", "443", NULL};
      return execute(args[0], args);
    }
    if (strcmp(argv[2], "proxy") == 0) {
      char *args[] = {"/usr/bin/nc", "-G", "4", "-z", "127.0.0.1", port, NULL};
      return execute(args[0], args);
    }
    return 112;
  }

  if (argc != 1) return 112;

  {
    char proxy_arg[96];
    snprintf(proxy_arg, sizeof(proxy_arg),
             "--proxy-server=http://127.0.0.1:%d", PROXY_PORT);
    char *claude_args[] = {
      "/Applications/Claude.app/Contents/MacOS/Claude",
      proxy_arg,
      "--disable-quic",
      NULL
    };
    return execute(claude_args[0], claude_args);
  }
}
