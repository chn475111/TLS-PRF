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

    unsigned char clientRandon[32] = {0};
    unsigned char serverRandon[32] = {0};
    unsigned char seedRandom[64] = {0};

    unsigned char preMasterSecret[48] = {0};
    unsigned char masterSecret[48] = {0};
    unsigned char key_block[2*32+2*16+2*16] = {0};      //SMS4-CBC-SM3

    unsigned char client_write_mac[32] = {0};
    unsigned char server_write_mac[32] = {0};
    unsigned char client_write_key[16] = {0};
    unsigned char server_write_key[16] = {0};
    unsigned char client_write_iv[16] = {0};
    unsigned char server_write_iv[16] = {0};

    SSL_library_init();
    SSL_load_error_strings();

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
    ret = tls_prf(preMasterSecret, 48, (unsigned char*)"master secret", 13, seedRandom, 64, masterSecret, 48);
    PRINT_HEX(masterSecret, 48);

    memcpy(seedRandom + 0, serverRandon, 32);
    memcpy(seedRandom + 32, clientRandon, 32);
    ret = tls_prf(masterSecret, 48, (unsigned char*)"key expansion", 13, seedRandom, 64, key_block, 128);
    PRINT_HEX(key_block, 128);

    memcpy(client_write_mac, key_block + 0, 32);
    memcpy(server_write_mac, key_block + 32, 32);
    memcpy(client_write_key, key_block + 48, 16);
    memcpy(server_write_key, key_block + 64, 16);
    memcpy(client_write_iv, key_block + 80, 16);
    memcpy(server_write_iv, key_block + 96, 16);

    ERR_print_errors_fp(stderr);
    return ret;
}
