// enc_server.c
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void die(const char* msg){ perror(msg); exit(1); }

static ssize_t send_all(int fd, const void* buf, size_t len){
    const char* p = (const char*)buf; size_t left = len;
    while (left) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; left -= (size_t)n;
    }
    return (ssize_t)len;
}
static ssize_t recv_all(int fd, void* buf, size_t len){
    char* p = (char*)buf; size_t left = len;
    while (left) {
        ssize_t n = recv(fd, p, left, 0);
        if (n == 0) return 0;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; left -= (size_t)n;
    }
    return (ssize_t)len;
}

static int send_u32(int fd, uint32_t v){
    uint32_t n = htonl(v);
    return send_all(fd, &n, sizeof(n)) == (ssize_t)sizeof(n);
}
static int recv_u32(int fd, uint32_t* out){
    uint32_t n;
    if (recv_all(fd, &n, sizeof(n)) != (ssize_t)sizeof(n)) return 0;
    *out = ntohl(n);
    return 1;
}

static int map27(int c){ return (c==' ') ? 26 : (c - 'A'); }
static char unmap27(int v){ return (v==26) ? ' ' : (char)('A' + v); }

static void handle_client(int connfd){
    // Handshake: expect "ENC\n"
    char hello[4];
    if (recv_all(connfd, hello, 4) <= 0 || memcmp(hello, "ENC\n", 4) != 0) {
        (void)send_all(connfd, "NO\n", 3);
        close(connfd);
        _exit(0);
    }
    (void)send_all(connfd, "OK\n", 3);

    // Receive lengths
    uint32_t plen=0, klen=0;
    if (!recv_u32(connfd, &plen) || !recv_u32(connfd, &klen) || klen < plen) {
        close(connfd);
        _exit(0);
    }

    // Receive payloads
    char* ptext = (char*)malloc(plen);
    char* ktext = (char*)malloc(klen);
    if (!ptext || !ktext) { free(ptext); free(ktext); close(connfd); _exit(0); }

    if (recv_all(connfd, ptext, plen) != (ssize_t)plen ||
        recv_all(connfd, ktext, klen) != (ssize_t)klen) {
        free(ptext); free(ktext); close(connfd); _exit(0);
    }

    // Encrypt: c[i] = (p[i] + k[i]) mod 27
    char* ctext = (char*)malloc(plen);
    if (!ctext) { free(ptext); free(ktext); close(connfd); _exit(0); }

    for (uint32_t i = 0; i < plen; i++) {
        int pv = map27(ptext[i]);
        int kv = map27(ktext[i]);
        int cv = (pv + kv) % 27;
        ctext[i] = unmap27(cv);
    }

    // Send ciphertext back
    (void)send_u32(connfd, plen);
    (void)send_all(connfd, ctext, plen);

    free(ptext); free(ktext); free(ctext);
    close(connfd);
    _exit(0);
}

int main(int argc, char* argv[]){
    if (argc != 2) {
        fprintf(stderr, "Usage: %s listening_port\n", argv[0]);
        exit(1);
    }
    int port = atoi(argv[1]);
    if (port <= 0) { fprintf(stderr, "enc_server error: bad port\n"); exit(1); }

    signal(SIGCHLD, SIG_IGN); // reap children

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket");

    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) die("setsockopt");

    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(sockfd, 5) < 0) die("listen");

    for (;;) {
        int connfd = accept(sockfd, NULL, NULL);
        if (connfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(connfd); continue; }
        if (pid == 0) { // child
            close(sockfd);
            handle_client(connfd);
        }
        close(connfd); // parent continues accepting
    }
}
