
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <limits.h>
#include <unistd.h>

#define LOG(...) fprintf(stderr, __VA_ARGS__)

int pid;
int initpid;

char *rootpath = NULL;

char cwd[PATH_MAX];

char *const passargv[] = {
	NULL
};

char *const passenvp[] = {
	"TERM=linux",
	"HOME=/home/ubuntu",
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	NULL
};

const char *defaultinitproc = "/init";
char *initproc;

int res = 0;

int main(int argc, char** argv, char** envp)
{
	if (argc < 2) {
		LOG("usage: %s <native root>\n", argv[0]);	
		exit(1);
	}

	rootpath = strdup(argv[1]);

	LOG("Entering directory %s\n", rootpath);
	chdir(rootpath);

	getcwd((char *)&cwd, PATH_MAX);
	LOG("cwd is now %s\n", cwd);

	if ((initproc = getenv("INIT")) == NULL) {
		initproc = (char *)defaultinitproc;
		LOG("using default inner init process\n");
	}

	LOG("Entering chroot (init is %s)\n", initproc);

	res = chroot((char *)&cwd);

	if (res != 0) {
		LOG("Error entering chroot: %d (%s)\n", res, strerror(res));
		exit(res);
	}

	LOG("changing to /\n");
	
	res = chdir("/");

	if (res != 0) {
		LOG("Changing to / failed: %d (%s)\n", res, strerror(res));
		exit(res);
	}

	res = execve(defaultinitproc, passargv, passenvp);

	if (res != 0) {
		LOG("Error executing init process: %d (%s)\n", res, strerror(res));
		exit(res);
	}

	/* won't be reached */

}




