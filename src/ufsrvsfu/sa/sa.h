/**
 * @file sa.h  Internal interface to Socket Address
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include "re_sa.h"

/* Net ntop/pton */
int net_inet_ntop(const struct sa *sa, char *buf, int size);
int net_inet_pton(const char *addr, struct sa *sa);
