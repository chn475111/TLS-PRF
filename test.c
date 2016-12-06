#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "prf_hmac.h"

#ifndef PRINT_HEX
#define PRINT_HEX(buf, len)                                                     \
    do{                                                                         \
        if(buf != NULL && len > 0)                                              \
        {                                                                       \
            int loop = 0;                                                       \
            for(loop = 0; loop < len; loop++)                                   \
                printf("%02hhx%c", buf[loop], (loop+1) % 16 == 0 ? '\n' : ' '); \
             printf("\n");                                                      \
        }                                                                       \
    }while(0);
#endif

int main(int argc, char *argv[])
{
    int ret = 0;
    int loop = 0;

    char label[] = "master secret";
    unsigned char clientRandon[32] = {0};
    unsigned char serverRandon[32] = {0};
    unsigned char seedRandom[64] = {0};

    unsigned char preMasterSecret[48] = {0};
    unsigned char masterSecret[48] = {0};

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    for(loop = 0; loop < 32; loop ++)
    {
        clientRandon[loop] = loop;
        serverRandon[loop] = loop;
    }

    for(loop = 0; loop < 48; loop ++)
    {
        preMasterSecret[loop] = loop;
    }

    memcpy(seedRandom + 0, clientRandon, 32);
    memcpy(seedRandom + 32, serverRandon, 32);

    ret = tls_prf(preMasterSecret, 48, (unsigned char*)label, strlen(label), seedRandom, 64, masterSecret, 48);
    PRINT_HEX(masterSecret, 48);

    ERR_print_errors_fp(stderr);
    return ret;
}
