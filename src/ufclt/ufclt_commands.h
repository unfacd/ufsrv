/*
 * ufclt_command.h
 *
 *  Created on: 23 Aug 2015
 *      Author: ayman
 */

#ifndef UFCLT_INCLUDE_UFCLT_COMMANDS_H_
#define UFCLT_INCLUDE_UFCLT_COMMANDS_H_
#include <session.h>

char *
ufcltSendLocation (Session *sesn_ptr);
char *
ufcltSendUserMessage (Session *sesn_ptr, char *);
#endif /* UFCLT_INCLUDE_UFCLT_COMMANDS_H_ */
