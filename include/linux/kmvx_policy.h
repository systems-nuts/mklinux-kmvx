#ifndef KMVX_POLICY_H
#define KMVX_POLICY_H
#include <linux/types.h>
#include <stdbool.h>

// Only CTU sync
#define LEVEL_LOW 0

// Hard sync on CFU
#define LEVEL_MED 1

// Lockstep
#define LEVEL_HI  2

// Only do CFU
#define LEVEL_DISCLOSURE 3


#define CTU_SHIFT 0
#define CFU_SHIFT 1
#define CTU_BUF_SHIFT 2
#define CFU_BUF_SHIFT 3

#define NO_FLAG 0
#define CTU_FLAG 1
#define CFU_FLAG 2
#define CTU_BUF (1 << CTU_BUF_SHIFT)
#define CFU_BUF (1 << CFU_BUF_SHIFT)

#define CTU_LOCKSTEP 0
#define CFU_LOCKSTEP 0

typedef struct {
	char  *name;
	size_t len_name;
	int (* func)(pid_t);
        struct list_head    list;
} detector_t;

typedef struct {
	int syscall;
        struct list_head    list;
} syscall_list_t;

typedef struct {
  pid_t pid;
  int		  level;
  bool            enable_ctu_compare; // Compare the contents of the buffer
  bool            enable_cfu_compare;
  int	          sync_mode;
  detector_t      *detectors;
  syscall_list_t  *disabled_syscalls;
  struct list_head    list;
} policy_setting_t;

void enable_for_process(pid_t pid);
void disable_for_process(pid_t pid);
void set_sync_mode(pid_t pid, int flag);
bool set_enable_syscall(pid_t pid, int syscall, bool enable);
void set_level(pid_t pid, int level);
void add_detector(pid_t pid, detector_t *detector);
bool should_check(pid_t pid, int syscall, int type); // TYPE: CTU_FLAG, CFU_FLAG, etc.
#endif
