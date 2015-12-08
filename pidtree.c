#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <proc/readproc.h>

#define PROCPID "/proc/%d/stat"
#define CMDSIZE 256
#define STR_(x) #x
#define STR(x) STR_(x)


static int indent = 0;

struct task {
	int pid;
	int ppid;
	char cmd[CMDSIZE + 1];
};

void print_tree(struct task *ctask) {
	printf("%*s" "pid:  %d\n", indent, "", ctask->pid);
	printf("%*s" "ppid: %d\n", indent, "", ctask->ppid);
	printf("%*s" "name: %s\n", indent, "", ctask->cmd);
	indent += 2;
}

/* Using libprocps */
int print_tree_procps(pid_t pid) {
	PROCTAB *proctab = NULL;
	proc_t *proc = NULL;

	int ret = 0;

	if (!pid)
		return ret;

	indent = 0;

	while (pid != 0) {
		struct task ctask;

		proctab = openproc(PROC_FILLSTAT | PROC_PID, &pid);

		if (!proctab) {
			printf("proctab is NULL");
			ret = -1;
			break;
		}

		proc = readproc(proctab, proc);

		if (!proc) {
			printf("The process %d doesn't exist.\n", pid);
			ret = -1;
			goto err;
		}

		ctask.pid = proc->tid;
		ctask.ppid = proc->ppid;
		strncpy(ctask.cmd, proc->cmd, CMDSIZE);

		print_tree(&ctask);

		pid = ctask.ppid;

		freeproc(proc);
		proc = NULL;

		closeproc(proctab);
		proctab = NULL;
	}

	if (proctab)
err:
		closeproc(proctab);
	return ret;
}

int print_tree_proc(pid_t pid) {
	FILE *proc;
	char procfile[128];
	struct task ctask;
	int ret = 0;

	if (!pid)
		return ret;

	indent = 0;

	while (pid != 0) {
		sprintf(procfile, PROCPID, pid);
		proc = fopen(procfile, "r");
		if (!proc) {
			printf("The %s file could not be open.\n", procfile);
			return -1;
		}

		ret = fscanf(proc, "%d %" STR(CMDSIZE) "s %*s %d",
			     &ctask.pid, ctask.cmd, &ctask.ppid);
		if (ret != 3) {
			printf("Wasn't possible to read the fields of %s\n", procfile);
			ret = -1;
			goto err;
		}

		ret = 0;

		/* Get rid of lead and trail chars */
		char *cmd = ctask.cmd;
		++cmd;

		cmd[strlen(cmd) - 1] = 0;
		memmove(ctask.cmd, cmd, CMDSIZE);

		print_tree(&ctask);

		pid = ctask.ppid;
	}

 err:
	fclose(proc);
	return ret;
}

void usage() {
	printf("Choose 1 to libprocps and 2 for direct proc access\n");
	printf("Eg ./pidtree 1\n");
}

int main(int argc, char *argv[]) {
	int ret = 0;
	pid_t pid;

	if (argc < 2) {
		usage();
		return ret;
	}

	if (argc > 2)
		pid = atoi(argv[2]);
	else
		pid = getpid();

	switch (atoi(argv[1])) {
	case 1:
		ret = print_tree_procps(pid);
		break;
	case 2:
		ret = print_tree_proc(pid);
		break;
	default:
		usage();
		break;
	}

	return ret;
}
