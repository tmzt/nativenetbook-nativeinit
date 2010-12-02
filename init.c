
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
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

#define PROCESS_FLAG_RESTART 1

struct process {
	struct process *next;

	int ppid;
	int pid;
	char *pty;
	char *tty;
	int **fds;
	char *path;
	int flags;
};	

int inittabfd = 0;
FILE *inittabfile = NULL;

char buf[1024];
char *line = NULL;

struct process *process = NULL;
struct process *processes = NULL;

int init()
{
	LOG("Reading /etc/inittab\n");
	inittabfile = fopen("/etc/inittab", "r");
	if (inittabfile == NULL) {
		LOG("Error reading /etc/inittab: %d (%s)\n", errno, strerror(errno));	
		exit(errno);
	}

	while ((line = fgets((char *) &buf, 1024, inittabfile)) != NULL) {
		LOG("Read line %s", line);
		/* for now the format of inittab is one path per line */
		process = calloc(1, sizeof(struct process));
		line[strlen(line)-1] = '\0'; /* remove newline */
		process->path = strdup(line);
		process->next = processes;
		processes = process;
	};

	LOG("Done reading from /etc/inittab\n");
	for (process = processes; process; process = process->next) {
		LOG("Path is %s\n", process->path);
	};
}		

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

#if 0
	res = execve(defaultinitproc, passargv, passenvp);

	if (res != 0) {
		LOG("Error executing init process: %d (%s)\n", res, strerror(res));
		exit(res);
	}

	/* won't be reached */
#else

	return init();

#endif

}




