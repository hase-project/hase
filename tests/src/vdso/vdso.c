#include <sys/time.h>
#include <signal.h>

int main(int argc, char **argv) {
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  raise(SIGABRT);
}
