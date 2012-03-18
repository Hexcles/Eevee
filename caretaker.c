/* 
 * caretaker.c
 *  
 * This file is part of Eevee.
 * 
 * Copyright (C) 2012 Hexcles Ma <bob1211@gmail.com>
 * 
 * Eevee is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Eevee is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Eevee.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * exit code:
 *   0: success (both the runner and program)
 *   ---------------runner---------------
 *   1: invalid options/command line format error or file not exists
 *   2: internal fatal (chroot, setuid, etc.)
 *   (details in stderr)
 *   --------------program---------------
 *   251: Time Limit Exceeded
 *   252: Memory Limit Exceeded
 *   253: Runtime Error (with return code in stdout, if any)
 */

#define EX_SUCCESS 0
#define EX_ERROR 1
#define EX_FATAL 2
#define EX_INTER 250
#define EX_TLE 251
#define EX_MLE 252
#define EX_RE 253

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

/* option list */
static const char *optString = "t:m:i:o:h";
static const struct option longOpts[] = {
	{"time", required_argument, NULL, 't'},
	{"memory", required_argument, NULL, 'm'},
	{"input", required_argument, NULL, 'i'},
	{"output", required_argument, NULL, 'o'},
	{"help", no_argument, NULL, 'h'},
	{ NULL, no_argument, NULL, 0 }
};

/* global options and default values */
char *program_invocation_name;
char *infileName = NULL, *outfileName = NULL, *prgfileName = NULL;
int timeLimit = 1000, memoryLimit = 131072, result = EX_SUCCESS;

uid_t parent_uid, child_uid;
gid_t parent_gid, child_gid;
char tmpdirTemplate[] = "/tmp/EeveeTMP.XXXXXX", *tmpdirName;

char *path_cat(const char *path, char *file);
inline int tv2ms(struct timeval tv);
void print_usage();
void apply_rlimit(int resource, int limit);
void parse_opt(int argc, char * const argv[]);
void init_env();
int watch_prg();
void clean_env();

inline int tv2ms(struct timeval tv) {
  return (int) (tv.tv_usec / 1000) + tv.tv_sec * 1000;
}

char *path_cat(const char *path, char *file) {
	size_t path_len = strlen(path);
	size_t file_len = strlen(file);
	char *result, *p;
	p = result = malloc((path_len + file_len + 2) * sizeof(*result));
	strcpy(p, path); p += path_len;
	*(p++) = '/';
	strcpy(p, file); p += file_len;
	*p = '\0';
	return result;
}

void print_usage() {
	printf("Usage: %s [OPTION] PROGRAM \n", program_invocation_name);
	printf("Run and watch the contestant's PROGRAM. (Part of the Eeevee)\n");
	printf(
	    "Options:\n"
		"  -t, --time=TIME_LIMIT          in ms, positive int only (default is 1000)\n"
		"  -m, --memory=MEMORY_LIMIT      in KB, positive int only (default is 131072)\n"
		"  -i, --input=INPUT_FILE         must in the same directory as PROGRAM\n"
		"      (file name must be identical with the problem description)\n"
		"  -o, --output=OUTPUT_FILENAME   the NAME of output file (should NOT exist!)\n"
		"  -h, --help                     print this help\n\n"
		"Output:\n"
		"  1.exited: WEXITSTATUS TIME(ms) MEMORY(KB)\n"
		"  2.killed: message\n"
		"Notes: PROGRAM must be compiled statically!\n");
	exit(EX_SUCCESS);
}

void apply_rlimit(int resource, int limit) {
	struct rlimit lim;
	lim.rlim_cur = lim.rlim_max = limit;
	if (setrlimit(resource, &lim) != 0)
		error(EX_INTER, 0, "Error setting rlimit.");
}

void parse_opt(int argc, char * const argv[]) {
	int longIndex = 0, opt = 0;
	opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
	while (opt != -1) {
		switch (opt) {
			case 't':
				timeLimit = atoi(optarg);
				if (timeLimit <= 0) error(EX_ERROR, 0,
				  "TIME_LIMIT must be a positive integer.");
				break;
			
			case 'm':
				memoryLimit = atoi(optarg);
				if (memoryLimit <= 0) error(EX_ERROR, 0,
				  "MEMORY_LIMIT must be a positive integer.");
				break;
			
			case 'i':
				if (optarg == 0) error(EX_ERROR, 0, "INPUT_FILE missing.");
				infileName = optarg;
				break;
			
			case 'o':
				if (optarg == 0) error(EX_ERROR, 0, "OUTPUT_FILE missing.");
				outfileName = optarg;
				break;
			
			case 'h':
				print_usage();
				break;
			
			default:
				error(EX_ERROR, 0, 
				  "Please run 'caretaker --help' for more information.");
				break;
		}
		opt = getopt_long(argc, argv, optString, longOpts, &longIndex);
	}
	if (optind == argc) error(EX_ERROR, 0, "PROGRAM not specified.");
	else prgfileName = argv[optind];
	//printf("%d\n%d\n%s\n%s\n%s\n", timeLimit, memoryLimit, infileName, outfileName, prgfileName);
}

void init_env(){
	parent_uid = geteuid();
	parent_gid = getegid();
	if (parent_uid != 0)
		error(EX_FATAL, 0, "Must be run as root.");
	struct passwd *nobody = getpwnam("nobody");
	if (nobody == NULL)
		error(EX_FATAL, 0, "Cannot find user 'nobody'.");
	child_uid = nobody->pw_uid;
	child_gid = nobody->pw_gid;
	umask(0);
	tmpdirName = mkdtemp(tmpdirTemplate);
	if (tmpdirName == NULL)
		error(EX_FATAL, 0, "Error create temp directory.");
	
	char *buffer = malloc(strlen(tmpdirName) + strlen(prgfileName) + 10);
	sprintf(buffer, "cp %s %s", prgfileName, tmpdirName);
	if (system(buffer) != 0) {
		clean_env();
		error(EX_ERROR, 0, "PROGRAM not exist.");
	}
	if (infileName != NULL) {
		buffer = realloc(buffer, strlen(tmpdirName) + strlen(infileName) + 10);
		sprintf(buffer, "cp %s %s", infileName, tmpdirName);
		if (system(buffer) != 0) {
			clean_env();
			error(EX_ERROR, 0, "INPUT_FILE not exist.\n");
		}
	}
	free(buffer);
	
	//chown(tmpdirName, parent_uid, parent_gid);
	chmod(tmpdirName, 00711);
	char *tmppath;
	
	tmppath = path_cat(tmpdirName, prgfileName);
	chown(tmppath, child_uid, child_gid);
	chmod(tmppath, 00555);
	free(tmppath);
	
	if (infileName != NULL) {
		tmppath = path_cat(tmpdirName, infileName);
		chown(infileName, parent_uid, parent_gid);
		chmod(infileName, 00644);
		free(tmppath);
	}
	
	if (outfileName != NULL) {
		tmppath = path_cat(tmpdirName, outfileName);
		int tmpof = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 00666);
		close(tmpof);
		free(tmppath);
	}
}

int watch_prg(){
	int status;
	struct rusage usage;
	char *envs[] = { NULL }, *args[] = { prgfileName, NULL };
	pid_t child = fork();
	if (child == -1) {
		fprintf(stderr, "Error forking.\n");
		return EX_FATAL;
	}
	if (child == 0) {
		//child process
		if (chroot(tmpdirName) != 0)
			error(EX_INTER, 0, "Error chroot.");
		chdir("/");
		apply_rlimit(RLIMIT_CPU, (int) (timeLimit + 1000) / 1000);	//in seconds
		apply_rlimit(RLIMIT_AS, (memoryLimit + 10240) * 1024);		//in bytes
		apply_rlimit(RLIMIT_NOFILE, 5);	//one greater than max file number permitted
		setgid(child_gid);
		setuid(child_uid);
		if ((geteuid() != child_uid) || (getegid() != child_gid))
			error(EX_INTER, 0, "Error setting uid/gid.");
		alarm((int) (timeLimit + 1000) / 1000);
		execve(prgfileName, args, envs);
		error(EX_INTER, 0, "Error executing.");
	} else {
		//parent process
		wait3(&status, WUNTRACED, &usage);
		if (WIFEXITED(status) && (WEXITSTATUS(status) == EX_INTER)) return EX_FATAL;
		int time = tv2ms(usage.ru_utime) + tv2ms(usage.ru_stime);
		long memory = usage.ru_minflt * (getpagesize() >> 10);
		if ((time > timeLimit) || (WIFSIGNALED(status) && (WTERMSIG(status) == SIGALRM))) {
			printf("Time Limit Exceeded\n");
			return EX_TLE;
		}
		if (memory > memoryLimit) {
			printf("Memory Limit Exceeded\n");
			return EX_MLE;
		}
		if (WIFEXITED(status))
			printf("%d %d %ld\n", WEXITSTATUS(status), time, memory);
		else printf("Program Killed\n");
		if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) return EX_RE;
	}
	return EX_SUCCESS;
}

void clean_env(){
	char *buffer;
	if (outfileName != NULL) {
		char *tmppath = path_cat(tmpdirName, outfileName);
		buffer = malloc(strlen(tmppath) + 10);
		sprintf(buffer, "cp -p %s .", tmppath);
		system(buffer);
		free(tmppath);
	} else buffer = malloc(strlen(tmpdirName) + 10);
	sprintf(buffer, "rm -rf %s", tmpdirName);
	system(buffer);
	free(buffer);
}

int main(int argc, char *argv[]){
	program_invocation_name = argv[0];
	parse_opt(argc, argv);
	init_env();
	result = watch_prg();
	clean_env();
	return result;
}
