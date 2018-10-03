#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <sys/syscall.h>

/* 
 * Test if we can correlate scheduling events and reassemble the instruction flow across different cpus
 * musl-gcc -g -fno-plt -static cpu_switch.c -o cpu_switch
 * hase record ./cpu_switch 1
 */

int main(int argc, char **argv) {
  unsigned cpu_before = 0, cpu_after = 0;
  pid_t pid = getpid();

  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(0, &set);
  int r = sched_setaffinity(pid, sizeof(set), &set);
  assert(r >= 0);
  r = syscall(SYS_getcpu, &cpu_before, NULL, NULL);
  assert(r >= 0);

  if (argc > 1) {
      puts("some branch\n");
  }

  CPU_ZERO(&set);
  CPU_SET(1, &set);
  r = sched_setaffinity(pid, sizeof(set), &set);
  assert(r >= 0);
  r = syscall(SYS_getcpu, &cpu_after, NULL, NULL);
  assert(r >= 0);

  if (argc > 1) {
      puts("some other branch\n");
  }

  assert(cpu_before != cpu_after);

  raise(SIGABRT);
}
