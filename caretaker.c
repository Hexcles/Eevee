/*
 * caretaker.c
 *  
 * This file is part of Eevee.
 * 
 * Copyright (C) 2012, Hexcles Ma <bob1211@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/resource.h>

#include "exit_code.h"
#include "syscall_listener.h"

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
int timeLimit = 1000, memoryLimit = 131072, result = EX_SUCCESS, timeout_killed;

uid_t parent_uid, child_uid;
gid_t parent_gid, child_gid;
pid_t child_pid;
char tmpdirTemplate[] = "/tmp/EeveeTMP.XXXXXX", *tmpdirName;

char *path_cat(const char *path, char *file);
inline int tv2ms(struct timeval tv);
void timeout();
void print_usage();
void apply_rlimit(int resource, int limit);
void parse_opt(int argc, char * const argv[]);
void init_env();
int watch_prg();
void clean_env();

inline int tv2ms(struct timeval tv) {
	return (int) (tv.tv_usec / 1000) + tv.tv_sec * 1000;
}

void timeout() {
	if (child_pid > 0) kill(child_pid, SIGKILL);
	timeout_killed = 1;
	alarm(0);
}

char *path_cat(const char *path, char *file) {
	size_t path_len = strlen(path), file_len = strlen(file);
	char *result;
	result = malloc((path_len + file_len + 2) * sizeof(*path));
	strcpy(result, path);
	result[path_len] = '/';
	strcpy(result + path_len + 1, file);
	//result[path_len + 1 + file_len] = '\0';
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
	child_pid = fork();
	if (child_pid == -1) {
		fprintf(stderr, "Error forking.\n");
		return EX_FATAL;
	}
	if (child_pid == 0) {
		//child process
		if (chroot(tmpdirName) != 0)
			error(EX_INTER, 0, "Error chroot.");
		chdir("/");
		int olderr = dup(STDERR_FILENO);
		int null = open("/dev/null", O_WRONLY), zero = open("/dev/zero", O_RDONLY);
		dup2(zero, STDIN_FILENO);
		dup2(null, STDOUT_FILENO);
		dup2(null, STDERR_FILENO);
		apply_rlimit(RLIMIT_CPU, (int) (timeLimit + 1000) / 1000);	//in seconds
		apply_rlimit(RLIMIT_AS, (memoryLimit + 10240) * 1024);		//in bytes
		apply_rlimit(RLIMIT_NOFILE, 10);	//one greater than max file number permitted
		setgid(child_gid);
		setuid(child_uid);
		if ((geteuid() != child_uid) || (getegid() != child_gid))
			error(EX_INTER, 0, "Error setting uid/gid.");
		listen_me(); //init ptrace_me
		execve(prgfileName, args, envs);
		dup2(olderr, STDERR_FILENO);
		error(EX_INTER, 0, "Error executing(forgot to link statically?).");
	} else {
		//parent process
		signal(SIGALRM, timeout);
		alarm((int) (timeLimit + 2000) / 1000);
		long memory_max = 0;
		while(1) { //listening
			wait3(&status, WUNTRACED, &usage);
			int st = parse_status(status);
			int time = tv2ms(usage.ru_utime) + tv2ms(usage.ru_stime);
			long memory_now = usage.ru_minflt * (getpagesize() >> 10);
			if (memory_now > memory_max)
				memory_max = memory_now;
			if ((time > timeLimit) || timeout_killed) {
				printf("Time Limit Exceeded\n");
				ptrace(PTRACE_KILL, child_pid, NULL, NULL);
				return EX_TLE;
			}
			if (memory_max > memoryLimit) {
				printf("Memory Limit Exceeded\n");
				ptrace(PTRACE_KILL, child_pid, NULL, NULL);
				return EX_MLE;
			}
			if (st >= 0) { //exited
				printf("%d %dms %ldKiB\n", WEXITSTATUS(status), time, memory_max);
				return st;
			}
			if (st == EX_YOYOCHECKNOW) { 
				check_call(child_pid);
			}
			listen_again(child_pid);
		}
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
