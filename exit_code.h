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
#ifndef __EXIT_CODE_H
#define __EXIT_CODE_H

#define EX_SUCCESS 0
#define EX_ERROR 1
#define EX_FATAL 2
#define EX_INTER 250
#define EX_TLE 251
#define EX_MLE 252
#define EX_RE 253

/*
 * Internal exit code
 * Passed to main program(caretaker) by syscall_listener
 */
#define EX_NOTEND (-255)
#define EX_YOYOCHECKNOW (-127)

#endif
