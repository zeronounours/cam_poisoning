#ifndef IPC_H
#define IPC_H

#include <config.h>

#include <sys/types.h>
#include <sys/un.h>

// path for the socket. This socket may be used for packet injection by any
// application
#define VAR_DIR_PATH	"/var/run/" PACKAGE_NAME
#define SOCKET_PATH		VAR_DIR_PATH "/cam_poisoning.sock"

struct ipc {
	int sock;
	struct sockaddr_un remote;
};

// open the IPC (it is a UNIX socket)
void open_ipc(struct ipc *ipc, const char *path);

// send through IPC
ssize_t sendto_ipc(struct ipc *ipc, const void *buf, size_t length);

#endif /* IPC_H */
