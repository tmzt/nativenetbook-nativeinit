
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
	char *tag;
	int flags;
	char *path;
};	

char buf[1024];
char *line = NULL;

struct process *process = NULL;
struct process *processes = NULL;

int forkchild(struct process *process)
{
	int pid, res;

	LOG("Path is %s\n", process->path);

	pid = fork();

	if (pid) {
		process->pid = pid;
		LOG("child pid is %d\n", pid);
		res = execve(process->path, passargv, passenvp);
		if (res != 0) {
			LOG("error starting child process: %s: %d (%s)\n", process->path, res, strerror(0-res));
			exit(res); /* child process exiting */
		};
	} else {
		return 0;
	}
}

int process_xinitrc() {
	int pid, res;
	char *display = NULL;
	char *const emptyargv[] = {NULL};

	if ((display = getenv("DISPLAY")) == NULL) {
		LOG("no $DISPLAY xinit is exiting\n");
		return -1;
	} 

	LOG("$DISPLAY is %s\n", display);

	LOG("forking xinit now\n");

	pid = fork();
	if (pid) {
		LOG("xinit pid is %d\n", pid);
		return 0;
	}

	/* for now, we just start /etc/X11/Xsession, this will change */

	/* DISPLAY is already in passenvp, this will be replaced dynamically */

	res = execve("/etc/X11/Xsession", emptyargv, passenvp);

	/* should not reach this point */

	if (res != 0) {
		LOG("starting Xsession failed, xinit is exiting\n");
		exit(res);
	}	
}

int init()
{
	FILE *file = NULL;

	int lineno;
	char *display = NULL;
	char *tag = NULL;
	char *flagstr = NULL;
	int flags;
	char *path = NULL;

	LOG("Checking $DISPLAY\n");
	if ((display = getenv("DISPLAY")) != NULL) {
		LOG("Forking xinit early\n");
		process_xinitrc();
	};	

	LOG("Init process has pid %d\n", getpid());

	LOG("Reading /etc/inittab\n");
	file = fopen("/etc/inittab", "r");
	if (file == NULL) {
		LOG("Error reading /etc/inittab: %d (%s)\n", errno, strerror(errno));	
		exit(errno);
	}

	while ((line = fgets((char *) &buf, 1024, file)) != NULL) {
		LOG("Read line %s", line);
		process = calloc(1, sizeof(struct process));
		line[strlen(line)-1] = '\0'; /* remove newline */

		if ((tag = strtok(line, ":")) == NULL) {
			LOG("Bad line reading tag on /etc/inittab:%d\n", lineno);
			exit(-1);
		};

		process->tag = strdup(tag);

		if ((flagstr = strtok(NULL, ":")) == NULL) {
			LOG("Bad line reading flags on /etc/inittab:%d\n", lineno);
			exit(-1);
		}

		if(sscanf(flagstr, "%d", &flags) <1) {
			LOG("Invalid value for flags, flags must be an integer on /etc/inittab:%d\n", lineno);
			flags = 0;
		}

		process->flags = flags;	
		
		if ((path = strtok(NULL, ":")) == NULL) {
			LOG("Bad line reading path on /etc/inittab:%d\n", lineno);
			exit(-1);
		}

		process->path = strdup(path); 	

		/* prepend to the list (for now) */
		process->next = processes;
		processes = process;
		lineno++;
	};

	LOG("Done reading /etc/inittab\n");
	for (process = processes; process; process = process->next) {
		LOG("Path is %s\n", process->path);

		LOG("Forking child for %s\n", process->path);
		forkchild(process);
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




