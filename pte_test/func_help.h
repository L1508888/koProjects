#ifndef FUNC_HELP_H
#define FUNC_HELP_H


#ifndef __nocfi
#define __nocfi __attribute__((__no_sanitize__("cfi")))
#endif

struct task_struct *get_task_by_pid(pid_t pid);


#endif