/*
 * command_console_thread.h
 *
 *  Created on: 13 Aug 2015
 *      Author: ayman
 */

#ifndef SRC_INCLUDE_COMMAND_CONSOLE_THREAD_H_
#define SRC_INCLUDE_COMMAND_CONSOLE_THREAD_H_
void *
ThreadCommandConsoleClient (void *ptr);
int AnswerCommandConsoleRequest (Socket *s_ptr);
Socket *
SetupCommandConsole (void);


#endif /* SRC_INCLUDE_COMMAND_CONSOLE_THREAD_H_ */
