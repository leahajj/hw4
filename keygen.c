#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define CHAR_SET "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(1);
    }

    int keyLength = atoi(argv[1]);
    if (keyLength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer\n");
        exit(1);
    }

    srand((unsigned int)time(NULL));

    const char *charset = CHAR_SET;
    int charsetLength = (int)strlen(charset);

    for (int i = 0; i < keyLength; i++) {
        int randIndex = rand() % charsetLength;
        putchar(charset[randIndex]);
    }
    putchar('\n');
    return 0;
}
