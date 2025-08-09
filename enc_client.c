// enc_client.c
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

static void dieu(const char* msg){ fprintf(stderr, "enc_client error: %s\n", msg); exit(2); }

static int is_valid_char(int c){ return (c==' ' || (c>='A' && c<='Z')); }

static char* read_file_strip_nl(const char* path, size_t* out_len){
    FILE* f = fopen(path, "r");
    if(!f) return NULL;
    if(fseek(f, 0, SEEK_END)!=0){ fclose(f); return NULL; }
    long sz = ftell(f);
    if(sz < 0){ fclose(f); return NULL; }
    rewind(f);

    char* buf = (char*)malloc((size_t)sz + 1);
    if(!buf){ fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if(n > 0 && buf[n-1] == '\n'){ buf[--n] = '\0'; }
    *out_len = n;
    return buf;
}

static int validate_text(const char* s, size_t n){
    for(size_t i=0;i<n;i++) if(!is_valid_char((unsigned char)s[i])) return 0;
    return 1;
}

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

int main(int argc, char* argv[]){
    if (argc != 4) {
        fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]);
        exit(1);
    }
    const char* plaintextPath = argv[1];
    const char* keyPath = argv[2];
    const char* portStr = argv[3];

    // Read & validate files
    size_t plen=0, klen=0;
    char* ptext = read_file_strip_nl(plaintextPath, &plen);
    if(!ptext){ fprintf(stderr, "enc_client error: cannot read plaintext file\n"); exit(1); }
    char* ktext = read_file_strip_nl(keyPath, &klen);
    if(!ktext){ fprintf(stderr, "enc_client error: cannot read key file\n"); free(ptext); exit(1); }

    if(!validate_text(ptext, plen) || !validate_text(ktext, klen)){
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        free(ptext); free(ktext); exit(1);
    }
    if(klen < plen){
        fprintf(stderr, "Error: key '%s' is too short\n", keyPath);
        free(ptext); free(ktext); exit(1);
    }

    // Connect to localhost:port
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    int rc = getaddrinfo("localhost", portStr, &hints, &res);
    if(rc != 0) dieu("could not resolve localhost");

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sockfd < 0){ freeaddrinfo(res); dieu("socket failed"); }

    if(connect(sockfd, res->ai_addr, res->ai_addrlen) < 0){
        freeaddrinfo(res); close(sockfd);
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", portStr);
        exit(2);
    }
    freeaddrinfo(res);

    // Handshake
    if(send_all(sockfd, "ENC\n", 4) < 0){
        close(sockfd);
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", portStr);
        exit(2);
    }
    char resp[3];
    if(recv_all(sockfd, resp, 3) <= 0 || memcmp(resp, "OK\n", 3) != 0){
        // Server rejected us (e.g., we hit dec_server)
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", portStr);
        close(sockfd);
        exit(2);
    }

    // Send lengths & payloads
    if(!send_u32(sockfd, (uint32_t)plen) || !send_u32(sockfd, (uint32_t)klen)){
        close(sockfd); free(ptext); free(ktext); dieu("failed sending lengths");
    }
    if(send_all(sockfd, ptext, plen) < 0 || send_all(sockfd, ktext, klen) < 0){
        close(sockfd); free(ptext); free(ktext); dieu("failed sending data");
    }

    // Receive ciphertext
    uint32_t clen = 0;
    if(!recv_u32(sockfd, &clen) || clen != (uint32_t)plen){
        close(sockfd); free(ptext); free(ktext); dieu("bad ciphertext length");
    }
    char* ctext = (char*)malloc(clen + 1);
    if(!ctext){ close(sockfd); free(ptext); free(ktext); dieu("oom"); }
    if(recv_all(sockfd, ctext, clen) != (ssize_t)clen){
        close(sockfd); free(ptext); free(ktext); free(ctext); dieu("ciphertext recv failed");
    }
    ctext[clen] = '\0';

    // Output to stdout + newline
    fwrite(ctext, 1, clen, stdout);
    fputc('\n', stdout);

    free(ptext); free(ktext); free(ctext);
    close(sockfd);
    return 0;
}
