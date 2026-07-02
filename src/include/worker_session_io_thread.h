//
// Created by devops on 11/20/22.
//

#ifndef UFSRV_WORKER_SESSION_IO_THREAD_H
#define UFSRV_WORKER_SESSION_IO_THREAD_H

void *ThreadWebSockets(void *ptr);

typedef void * (*sessionworker_thread_callback)(void *);
sessionworker_thread_callback GetSessionWorkerThreadHandler(void);

#endif //UFSRV_WORKER_SESSION_IO_THREAD_H
