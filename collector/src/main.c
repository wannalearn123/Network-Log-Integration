#include "collector.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    const char* source = NULL;

    if (argc > 1) {
        source = argv[1];
    }

    return collector_run(source);
}
