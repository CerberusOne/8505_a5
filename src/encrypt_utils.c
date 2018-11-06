/*
 * =====================================================================================
 *
 *       Filename:  encrypt_utils.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  10/07/2018 06:55:24 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Benedict Lo
 *   Organization:
 *
 * =====================================================================================
 */
#include "encrypt_utils.h"
#include <stdio.h>
#include <string.h>

//unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; //Key
//unsigned char *iv = (unsigned char*)"0123456789012345"; //IV

/*void encryptString(unsigned char* key, unsigned char *iv, char &payload, bool encrypt){
    unsigned char *plaintext = &payload;
    unsigned char *decryptedtext;
    unsigned char *ciphertext;
    int decryptedlen, cipherlen;

    if(encrypt){
    cipherlen = encryptMessage(plaintext, strlen((char*)plaintext), key,iv, ciphertext);
    } else {
    decryptedlen = decryptMessage(ciphertext, cipherlen, key, iv, decryptedtext);
    }
}*/

int encryptMessage(unsigned char *plaintext, int plaintextlen, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertextlen;
    //initilize context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
    }

    if((EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextlen)!= 1)){
        handleErrors();
    }
    ciphertextlen = len;

    if((EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) != 1){
        printf("Error on the last block of data");
        handleErrors();
    }
    ciphertextlen += len;
/*  printf("Message:\n");
    for(unsigned long i=0; i<(ciphertextlen); ++i){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
*/
    EVP_CIPHER_CTX_free(ctx);
    return ciphertextlen;
}


int decryptMessage(unsigned char *ciphertext, int ciphertextlen, unsigned char *key, unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintextlen;
    //initilize context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

/*
    printf("Message:\n");
    for(unsigned long i=0; i<(ciphertextlen); ++i){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
*/
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
    }

    if((EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextlen)) != 1){
            handleErrors();
    }
    plaintextlen = len;

    if(!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
        printf("Error on the last block of data");
        handleErrors();
    }
    plaintextlen += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintextlen;
}



void crypto(char *input,char *output, unsigned char *key, unsigned char *iv, bool encryptfile){
    FILE* cryptoinput;
    FILE* cryptooutput;
    if((cryptoinput = fopen(input, "rb")) == NULL){
       printf("Could not be open for reading \n");
       exit(1);
    }

    if((cryptooutput = fopen(output, "wb")) == NULL){
        printf("Could not be opened for writing");
        exit(1);
    }
    if(encryptfile){
        encryptFile(cryptoinput, cryptooutput, key, iv);
    } else {
        decryptFile(cryptoinput, cryptooutput, key, iv);
    }
    fclose(cryptoinput);
    fclose(cryptooutput);

}

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encryptFile(FILE *input, FILE *output, unsigned char *key, unsigned char *iv){
    EVP_CIPHER_CTX *ctx;
    unsigned char inbuff[BUFFLEN];
    unsigned char outbuff[BUFFLEN];
    int bytesRead, bytesWritten, outLen;
    //initilize context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
    }

    while(1){
        if((bytesRead = fread(inbuff, sizeof(unsigned char), BUFFLEN, input)) == -1){
            printf("Could not read file");
            exit(1);
        }
        if((EVP_EncryptUpdate(ctx, outbuff, &outLen, inbuff, bytesRead)) != 1){
            handleErrors();
        }

        if((bytesWritten = fwrite(outbuff, sizeof(unsigned char), outLen, output)) == -1){
            printf("Could not write to file");
        }
        if(bytesRead < BUFFLEN){
            break;
            //encrypt the last block of data
        }
    }
    if(!EVP_EncryptFinal_ex(ctx, outbuff, &outLen)){
        printf("Error on the last block of data");
        handleErrors();
    }
    if((bytesWritten = fwrite(outbuff, sizeof(unsigned char), outLen, output)) == -1){
        printf("Could not write the last block to file");
    }
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}


int decryptFile(FILE *input, FILE *output, unsigned char *key, unsigned char *iv){
    EVP_CIPHER_CTX *ctx;
    unsigned char inbuff[BUFFLEN];
    unsigned char outbuff[BUFFLEN];
    int bytesRead, bytesWritten, outLen;
    int result;
    //initilize context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
    }

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        handleErrors();
    }

    while(1){
        if((bytesRead = fread(inbuff, sizeof(unsigned char), BUFFLEN, input)) == -1){
            printf("Could not read file");
            exit(1);
        }
        if((result = EVP_DecryptUpdate(ctx, outbuff, &outLen, inbuff, bytesRead)) != 1){
            handleErrors();
        }

        if((bytesWritten = fwrite(outbuff, sizeof(unsigned char), outLen, output)) == -1){
            printf("Could not write to file");
        }
        if(bytesRead < BUFFLEN){
            break;
            //encrypt the last block of data
        }
    }
    if(!EVP_DecryptFinal_ex(ctx, outbuff, &outLen)){
        printf("Error on the last block of data");
        handleErrors();
    }
    if((bytesWritten = fwrite(outbuff, sizeof(unsigned char), outLen, output)) == -1){
        printf("Could not write the last block to file");
    }
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

