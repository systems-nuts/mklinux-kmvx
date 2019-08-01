#include <linux/kmvx_policy.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>

policy_setting_t policy_list;


void _set_ctu_sync(pid_t pid, bool enable);
void _set_cfu_sync(pid_t pid, bool enable);
policy_setting_t* _get_policy_for_process(pid_t);
bool _process_policy_exists(pid_t pid);

// TODO: Add procfs way of enabling for a certain process


int init_kmvx_policy() {
   INIT_LIST_HEAD(&policy_list.list);    //or LIST_HEAD(mylist);
}


void enable_for_process(pid_t pid)
{

  policy_setting_t *new_policy;

  if (_process_policy_exists(pid))
    return;

  new_policy = kmalloc(sizeof(*new_policy), GFP_KERNEL);
  new_policy->pid = pid;
  INIT_LIST_HEAD(&new_policy->list);
  list_add_tail(&(new_policy->list), &(policy_list.list));

}

void set_sync_mode(pid_t pid, int flag)
{
  if (flag == NO_FLAG) {
    _set_ctu_sync(pid, false);
    _set_cfu_sync(pid, false);
  }
  if (flag & CTU_FLAG) {
    _set_ctu_sync(pid, true);
  }
  if (flag & CFU_FLAG) {
    _set_cfu_sync(pid, true);
  }
}

bool set_enable_syscall(pid_t pid, int syscall, bool enable)
{
  syscall_list_t *syscall_entry;

  policy_setting_t *policy = _get_policy_for_process(pid);
  if (policy == NULL) {
    return false;
  }
  if (policy->disabled_syscalls == NULL && !enable) {
    return false;
  } else if (policy->disabled_syscalls == NULL && enable) {
    policy->disabled_syscalls = kmalloc(sizeof(*policy->disabled_syscalls),
					GFP_KERNEL);
    INIT_LIST_HEAD(&policy->disabled_syscalls->list);
    syscall_entry = kmalloc(sizeof(*syscall_entry),
					    GFP_KERNEL);
    syscall_entry->syscall = syscall;
    INIT_LIST_HEAD(&syscall_entry->list);
    list_add_tail(&(syscall_entry->list), &policy->disabled_syscalls->list);

  } else if (enable) {
    syscall_entry = kmalloc(sizeof(*syscall_entry),
					    GFP_KERNEL);
    syscall_entry->syscall = syscall;
    INIT_LIST_HEAD(&syscall_entry->list);
    list_add_tail(&(syscall_entry->list), &policy->disabled_syscalls->list);
  } else if (!enable) {
    list_for_each_entry(syscall_entry, &policy->disabled_syscalls->list, list) {
      if (syscall_entry->syscall == syscall) {
	list_del(&syscall_entry->list);
	kfree(syscall_entry);
      }
    }

  }
  return 0;
}

void set_level(pid_t pid, int level)
{
  policy_setting_t* policy;

  policy = _get_policy_for_process(pid);
  if (policy == NULL) {
    return;
  }

  switch (level) {
    case LEVEL_LOW:
      set_sync_mode(pid, CTU_FLAG);
      break;
    case LEVEL_MED:
      set_sync_mode(pid, CTU_FLAG | CFU_FLAG | CFU_LOCKSTEP | CTU_BUF | CFU_BUF);
      break;
    case LEVEL_HI:
      set_sync_mode(pid, CTU_FLAG | CFU_FLAG | CTU_LOCKSTEP | CFU_LOCKSTEP);
      break;
    case LEVEL_DISCLOSURE:
      set_sync_mode(pid, CFU_FLAG | CFU_LOCKSTEP);
      break;
  }
  policy->level = level;
}

void add_detector(pid_t pid, detector_t *detector)
{
  // TODO: implement this

}

// E.g. for ctu buffer compare should_check(123, 97, CTU_FLAG | CTU_BUF)
bool should_check(pid_t pid, int syscall, int type)
{

  // For now hard-coded to true
  return true;

#if 0
  policy_setting_t *policy;

  policy = _get_policy_for_process(pid);
  if (policy == NULL) {
    return false;
  }
  if (policy->sync_mode & type) {
    return true;
  }
  return false;
# endif
}


void _set_sync(pid_t pid, int flag_bit, bool enable)
{
  policy_setting_t *policy;

  policy = _get_policy_for_process(pid);
  if (policy == NULL) {
    return;
  }
  policy->sync_mode ^= (-enable ^ policy->sync_mode) & (1 << flag_bit);
}

void _set_ctu_sync(pid_t pid, bool enable)
{
  _set_sync(pid, CTU_SHIFT, enable);
}

void _set_cfu_sync(pid_t pid, bool enable)
{
  _set_sync(pid, CFU_SHIFT, enable);
}

void _set_ctu_buf_sync(pid_t pid, bool enable)
{
  _set_sync(pid, CTU_BUF_SHIFT, enable);
}

void _set_cfu_buf_sync(pid_t pid, bool enable)
{
  _set_sync(pid, CFU_BUF_SHIFT, enable);
}

policy_setting_t* _get_policy_for_process(pid_t pid)
{
  policy_setting_t *policy;
  list_for_each_entry(policy, &policy_list.list, list) {
    if (policy->pid == pid)
      return policy;
  }
  return NULL;
}

bool _process_policy_exists(pid_t pid)
{
  policy_setting_t *policy;
  list_for_each_entry(policy, &policy_list.list, list) {
    if (policy->pid == pid)
      return true;
  }
  return false;
}

bool _contains_syscall(syscall_list_t *lst, int syscall)
{
  syscall_list_t *syscall_entry;

  if (lst == NULL)
    return false;
  list_for_each_entry(syscall_entry, &lst->list, list) {
      if (syscall_entry->syscall == syscall) {
	return true;
      }
    }
  return false;
}
