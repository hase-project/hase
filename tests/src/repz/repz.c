#include <string.h>

int main(int argc, const char *argv[]) {
  for (int i = 0; i < argc; i++) {
    if (0 == strcmp(argv[0], "test1")) return 1;
  }
}
