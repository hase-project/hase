#define _POSIX_C_SOURCE 200112L
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define ENVNAME "SYNC_PIPE_FD"

int main(int argc, char *const argv[]) {
  char buf[1];
  if (argc < 2) {
    return 1;
  }

  char* pipe = getenv(ENVNAME);

  if (pipe == NULL) {
    return 1;
  }

  if (unsetenv(ENVNAME) < 0) {
    return 1;
  }

  int pipefd = atoi(pipe);

  /* block on pipefd until tracing starts */
  if (read(pipefd, buf, sizeof(buf)) < 0) {
    return 1;
  };

  close(pipefd);

  execvp(argv[1], &argv[1]);
}
