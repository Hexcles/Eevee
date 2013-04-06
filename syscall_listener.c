#define EX_NOTEND (-255)
#define EX_YOYOCHECKNOW (-127)
#include <sys/ptrace.h>
#include <sys/reg.h>

int call_count[512]={0};

void listen_me();
void listen_again();
int parse_status(int);
void check_call(pid_t);
//definitions begin at line 300

const int syscall_limit[]=
{
  0, 0, -1, //fork
  0, 0, -1,
  -1, -1, -1, //creat
 -1, -1, 1, //exec
 -1, 0, -1, //mknot

  -1, -1, -1, //break
  -1, 0, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //gtty
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  0, -1, -1, //getgid
  -1, -1, -1,
  -1, -1, -1,
  0, -1, -1,
  -1, -1, 0,

  -1, -1, -1, //ustat
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //getrusage
  0, -1, -1,
  -1, -1, -1,
  -1, 0, 0,
  -1, -1, -1,

  0, 0, -1,  // truncate
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //lstat
   0, 0, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, 0, //uname
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //afs_syscall
  -1, -1, -1,
  -1, -1, -1,
  -1, 0, 0,
  -1, -1, -1,

  -1, -1, -1, //mlockall
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, 0, -1,

  -1, -1, -1, //query_module
  -1, -1, -1,
  -1, -1, -1,
  0, -1, -1,
  -1, -1, -1,

  0, 0, -1, //chown
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, 0,
  0, -1, -1,

  -1, -1, 0, //fstat64
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  
  -1, -1, -1, //chwon32
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  0, 0, -1,

  -1, -1, -1, //lsetxattr
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //sched_getaffinity
  0, 0, -1,
  -1, -1, -1,
  -1, -1, 0,
  0, -1, -1,

  -1, -1, -1, //remap_file_pages
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //fadvise64_64
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  0, -1, -1, // request_key
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //renameat
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //move_pages
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1, -1, //inotify_init1
  0, 0, -1,
  -1, -1, -1,
  -1, -1, -1,
  -1, -1, -1,

  -1, -1
};

const char* const syscall_list[]= 
{
  "SYS_restart_syscall" ,"SYS_exit" ,"SYS_fork" ,
  "SYS_read" ,"SYS_write" ,"SYS_open" ,
  "SYS_close" ,"SYS_waitpid" ,"SYS_creat" ,
  "SYS_link" ,"SYS_unlink" ,"SYS_execve" ,
  "SYS_chdir" ,"SYS_time" ,"SYS_mknod" ,

  "SYS_chmod" ,"SYS_lchown" ,"SYS_break" ,
  "SYS_oldstat" ,"SYS_lseek" ,"SYS_getpid" ,
  "SYS_mount" ,"SYS_umount" ,"SYS_setuid" ,
  "SYS_getuid" ,"SYS_stime" ,"SYS_ptrace" ,
  "SYS_alarm" ,"SYS_oldfstat" ,"SYS_pause" ,

  "SYS_utime" ,"SYS_stty" ,"SYS_gtty" ,
  "SYS_access" ,"SYS_nice" ,"SYS_ftime" ,
  "SYS_sync" ,"SYS_kill" ,"SYS_rename" ,
  "SYS_mkdir" ,"SYS_rmdir" ,"SYS_dup" ,
  "SYS_pipe" ,"SYS_times" ,"SYS_prof" ,

  "SYS_brk" ,"SYS_setgid" ,"SYS_getgid" ,
  "SYS_signal" ,"SYS_geteuid" ,"SYS_getegid" ,
  "SYS_acct" ,"SYS_umount2" ,"SYS_lock" ,
  "SYS_ioctl" ,"SYS_fcntl" ,"SYS_mpx" ,
  "SYS_setpgid" ,"SYS_ulimit" ,"SYS_oldolduname" ,


  "SYS_umask" ,"SYS_chroot" ,"SYS_ustat" ,
  "SYS_dup2" ,"SYS_getppid" ,"SYS_getpgrp" ,
  "SYS_setsid" ,"SYS_sigaction" ,"SYS_sgetmask" ,
  "SYS_ssetmask" ,"SYS_setreuid" ,"SYS_setregid" ,
  "SYS_sigsuspend" ,"SYS_sigpending" ,"SYS_sethostname" ,

  "SYS_setrlimit" ,"SYS_getrlimit" ,"SYS_getrusage" ,
  "SYS_gettimeofday" ,"SYS_settimeofday" ,"SYS_getgroups" ,
  "SYS_setgroups" ,"SYS_select" ,"SYS_symlink" ,
  "SYS_oldlstat" ,"SYS_readlink" ,"SYS_uselib" ,
  "SYS_swapon" ,"SYS_reboot" ,"SYS_readdir" ,

  "SYS_mmap" ,"SYS_munmap" ,"SYS_truncate" ,
  "SYS_ftruncate" ,"SYS_fchmod" ,"SYS_fchown" ,
  "SYS_getpriority" ,"SYS_setpriority" ,"SYS_profil" ,
  "SYS_statfs" ,"SYS_fstatfs" ,"SYS_ioperm" ,
  "SYS_socketcall" ,"SYS_syslog" ,"SYS_setitimer" ,

  "SYS_getitimer" ,"SYS_stat" ,"SYS_lstat" ,
  "SYS_fstat" ,"SYS_olduname" ,"SYS_iopl" ,
  "SYS_vhangup" ,"SYS_idle" ,"SYS_vm86old" ,
  "SYS_wait4" ,"SYS_swapoff" ,"SYS_sysinfo" ,
  "SYS_ipc" ,"SYS_fsync" ,"SYS_sigreturn" ,

  "SYS_clone" ,"SYS_setdomainname" ,"SYS_uname" ,
  "SYS_modify_ldt" ,"SYS_adjtimex" ,"SYS_mprotect" ,
  "SYS_sigprocmask" ,"SYS_create_module" ,"SYS_init_module" ,
  "SYS_delete_module" ,"SYS_get_kernel_syms" ,"SYS_quotactl" ,
  "SYS_getpgid" ,"SYS_fchdir" ,"SYS_bdflush" ,

  "SYS_sysfs" ,"SYS_personality" ,"SYS_afs_syscall" ,
  "SYS_setfsuid" ,"SYS_setfsgid" ,"SYS__llseek" ,
  "SYS_getdents" ,"SYS__newselect" ,"SYS_flock" ,
  "SYS_msync" ,"SYS_readv" ,"SYS_writev" ,
  "SYS_getsid" ,"SYS_fdatasync" ,"SYS__sysctl" ,

  "SYS_mlock" ,"SYS_munlock" ,"SYS_mlockall" ,
  "SYS_munlockall" ,"SYS_sched_setparam" ,"SYS_sched_getparam" ,
  "SYS_sched_setscheduler" ,"SYS_sched_getscheduler" ,"SYS_sched_yield" ,
  "SYS_sched_get_priority_max" ,"SYS_sched_get_priority_min" ,"SYS_sched_rr_get_interval" ,
  "SYS_nanosleep" ,"SYS_mremap" ,"SYS_setresuid" ,

  "SYS_getresuid" ,"SYS_vm86" ,"SYS_query_module" ,
  "SYS_poll" ,"SYS_nfsservctl" ,"SYS_setresgid" ,
  "SYS_getresgid" ,"SYS_prctl" ,"SYS_rt_sigreturn" ,
  "SYS_rt_sigaction" ,"SYS_rt_sigprocmask" ,"SYS_rt_sigpending" ,
  "SYS_rt_sigtimedwait" ,"SYS_rt_sigqueueinfo" ,"SYS_rt_sigsuspend" ,

  "SYS_pread64" ,"SYS_pwrite64" ,"SYS_chown" ,
  "SYS_getcwd" ,"SYS_capget" ,"SYS_capset" ,
  "SYS_sigaltstack" ,"SYS_sendfile" ,"SYS_getpmsg" ,
  "SYS_putpmsg" ,"SYS_vfork" ,"SYS_ugetrlimit" ,
  "SYS_mmap2" ,"SYS_truncate64" ,"SYS_ftruncate64" ,

  "SYS_stat64" ,"SYS_lstat64" ,"SYS_fstat64" ,
  "SYS_lchown32" ,"SYS_getuid32" ,"SYS_getgid32" ,
  "SYS_geteuid32" ,"SYS_getegid32" ,"SYS_setreuid32" ,
  "SYS_setregid32" ,"SYS_getgroups32" ,"SYS_setgroups32" ,
  "SYS_fchown32" ,"SYS_setresuid32" ,"SYS_getresuid32" ,

  "SYS_setresgid32" ,"SYS_getresgid32" ,"SYS_chown32" ,
  "SYS_setuid32" ,"SYS_setgid32" ,"SYS_setfsuid32" ,
  "SYS_setfsgid32" ,"SYS_pivot_root" ,"SYS_mincore" ,
  "SYS_madvise1" ,"SYS_getdents64" ,"SYS_fcntl64" ,
  "" ,"" ,"SYS_gettid" ,

  "SYS_readahead" ,"SYS_setxattr" ,"SYS_lsetxattr" ,
  "SYS_fsetxattr" ,"SYS_getxattr" ,"SYS_lgetxattr" ,
  "SYS_fgetxattr" ,"SYS_listxattr" ,"SYS_llistxattr" ,
  "SYS_flistxattr" ,"SYS_removexattr" ,"SYS_lremovexattr" ,
  "SYS_fremovexattr" ,"SYS_tkill" ,"SYS_sendfile64" ,

  "SYS_futex" ,"SYS_sched_setaffinity" ,"SYS_sched_getaffinity" ,
  "SYS_set_thread_area" ,"SYS_get_thread_area" ,"SYS_io_setup" ,
  "SYS_io_destroy" ,"SYS_io_getevents" ,"SYS_io_submit" ,
  "SYS_io_cancel" ,"SYS_fadvise64" ,"" ,
  "SYS_exit_group" ,"SYS_lookup_dcookie" ,"SYS_epoll_create" ,

  "SYS_epoll_ctl" ,"SYS_epoll_wait" ,"SYS_remap_file_pages" ,
  "SYS_set_tid_address" ,"SYS_timer_create" ,"SYS_timer_settime" ,
  "SYS_timer_gettime" ,"SYS_timer_getoverrun" ,"SYS_timer_delete" ,
  "SYS_clock_settime" ,"SYS_clock_gettime" ,"SYS_clock_getres" ,
  "SYS_clock_nanosleep" ,"SYS_statfs64" ,"SYS_fstatfs64" ,

  "SYS_tgkill" ,"SYS_utimes" ,"SYS_fadvise64_64" ,
  "SYS_vserver" ,"SYS_mbind" ,"SYS_get_mempolicy" ,
  "SYS_set_mempolicy" ,"SYS_mq_open" ,"SYS_mq_unlink" ,
  "SYS_mq_timedsend" ,"SYS_mq_timedreceive" ,"SYS_mq_notify" ,
  "SYS_mq_getsetattr" ,"SYS_kexec_load" ,"SYS_waitid" ,

  "" ,"SYS_add_key" ,"SYS_request_key" ,
  "SYS_keyctl" ,"SYS_ioprio_set" ,"SYS_ioprio_get" ,
  "SYS_inotify_init" ,"SYS_inotify_add_watch" ,"SYS_inotify_rm_watch" ,
  "SYS_migrate_pages" ,"SYS_openat" ,"SYS_mkdirat" ,
  "SYS_mknodat" ,"SYS_fchownat" ,"SYS_futimesat" ,

  "SYS_fstatat64" ,"SYS_unlinkat" ,"SYS_renameat" ,
  "SYS_linkat" ,"SYS_symlinkat" ,"SYS_readlinkat" ,
  "SYS_fchmodat" ,"SYS_faccessat" ,"SYS_pselect6" ,
  "SYS_ppoll" ,"SYS_unshare" ,"SYS_set_robust_list" ,
  "SYS_get_robust_list" ,"SYS_splice" ,"SYS_sync_file_range" ,

  "SYS_tee" ,"SYS_vmsplice" ,"SYS_move_pages" ,
  "SYS_getcpu" ,"SYS_epoll_pwait" ,"SYS_utimensat" ,
  "SYS_signalfd" ,"SYS_timerfd_create" ,"SYS_eventfd" ,
  "SYS_fallocate" ,"SYS_timerfd_settime" ,"SYS_timerfd_gettime" ,
  "SYS_signalfd4" ,"SYS_eventfd2" ,"SYS_epoll_create1" ,

  "SYS_dup3" ,"SYS_pipe2" ,"SYS_inotify_init1" ,
  "SYS_preadv" ,"SYS_pwritev" ,"SYS_rt_tgsigqueueinfo" ,
  "SYS_perf_event_open" ,"SYS_recvmmsg" ,"SYS_fanotify_init" ,
  "SYS_fanotify_mark" ,"SYS_prlimit64" ,"SYS_name_to_handle_at" ,
  "SYS_open_by_handle_at" ,"SYS_clock_adjtime" ,"SYS_syncfs" ,

  "SYS_sendmmsg" ,"SYS_setns"
};

void listen_me()
{
  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1)
    error(EX_INTER, 0, "Error initiating ptrace");
}

void listen_again(pid_t child_pid)
{
  if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL)==-1)
    error(EX_INTER, 0, "Error ptracsing child");
}


void check_call(pid_t child_pid)
{
  int id = ptrace(PTRACE_PEEKUSER, child_pid, (void*)(4*ORIG_EAX), NULL);
  if (id==-1)
    error(EX_INTER, 0, "Error peeking user");
  call_count[id]++; 
  if ((call_count[id]&1) == 0)
    return;

  printf("Calling   %-16s\t(id:%-4d)\t\n", syscall_list[id], id);
  if (syscall_limit[id] == 0) //no limits
    return;
  if (call_count[id] > syscall_limit[id])
  {
    ptrace(PTRACE_KILL, child_pid, NULL, NULL);
    error(EX_INTER, 0, "forbidden operation");
  }
}

int parse_status(int status)
{
  if (WIFEXITED(status)) //exited
  {
    if (WEXITSTATUS(status) == 0)
      return EX_SUCCESS;
    else
      return EX_RE;
  }

  if (WIFSIGNALED(status))
    return EX_FATAL;

  if (WIFSTOPPED(status))
  {
    int sig = WSTOPSIG(status);
    switch (sig)
    {
      case SIGUSR1:         //regular check
        break;       //just a place holder
      case SIGTRAP:         //ptrace got an syscall (to call or has returned)
        return EX_YOYOCHECKNOW;
      case SIGXFSZ:         //write too much to file
        return EX_RE;//actually, it should be EX_OLE
      default:
        return EX_RE;
    }
  }
  return EX_NOTEND;
}

