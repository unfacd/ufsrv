//
// Created by devops on 10/30/18.
//

#ifndef UFSRV_UTILS_HEX_H
#define UFSRV_UTILS_HEX_H

#include <main.h>

char *bin2hex(const unsigned char *bin, size_t len, char *result_out);
int hexchr2bin (const char hex, char *out);
size_t hex2bin(const char *hex, unsigned char **out);

#endif //UFSRV_UTILS_HEX_H
