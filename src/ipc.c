#include <ipc.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <sys/socket.h>

#include <logger.h>

/*
 * Initialize the UNIX Socket IPC
 */
void open_ipc(struct ipc *ipc, const char *path) {
	struct sockaddr_un addr;

	// Ensure the base directory for the socket path exists
	struct stat st = {0};
	if (stat(VAR_DIR_PATH, &st) == -1) {
		if (errno == ENOENT) {
			if (mkdir(VAR_DIR_PATH, 0755) == -1) {
				perror("Failed to create socket directory");
				exit(1);
			}
		} else {
			perror("Failed to stat socket directory");
			exit(1);
		}
	} else {
		// Ensure the the socket is deleted if it exists
		if (stat(SOCKET_PATH, &st) == -1) {
			// The only accepted error is ENOENT (i.e. file doesn't exist)
			if (errno != ENOENT) {
				perror("Failed to stat the socket file");
				exit(1);
			}
		} else {
			// File exists => need to delete
			if (unlink(SOCKET_PATH) == -1) {
				perror("Failed to delete the socket file");
			}
		}
	}


	// create the socket and connect it to the file
	if ( (ipc->sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		perror("Cannot open UNIX socket");
		exit(1);
	}

	// addr for the bind
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

	// bind the socket
	if (bind(ipc->sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
		perror("Cannot bind UNIX socket");
		exit(1);
	}

	// set the remote socket address
	memset(&ipc->remote, 0, sizeof(ipc->remote));
	ipc->remote.sun_family = AF_UNIX;
	strncpy(ipc->remote.sun_path, path, sizeof(ipc->remote.sun_path) - 1);
}

ssize_t sendto_ipc(struct ipc *ipc, const void *buf, size_t length) {
	log_debug("Sending %i bytes through IPC\n");
	return sendto(ipc->sock, buf, length, 0,
			(struct sockaddr *) &ipc->remote, sizeof(struct sockaddr_un));
}
