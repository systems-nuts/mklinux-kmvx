/*
 * ft_common_syscall_management.c
 *
 * Author: Marina
 * Refactoring and bug fixing: antoniob
 *
 * syscall_hook_enter/_exit code copyright Antonio, Wen
 * hashtable Marina
 *
 */

#include <linux/ft_replication.h>
#include <linux/kmvx_policy.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/pcn_kmsg.h>
#include <linux/popcorn_namespace.h>
#include <linux/ft_common_syscall_management.h>
#include <asm/unistd_64.h>
#include <linux/ft_time_breakdown.h>

/*
 * Below lines are copied from DMP.
 * Remeber to appericiate them if we make this thing working.
 */
/* MOT options */
#define SPECIAL		(0)	/* comment that this syscall is handled specially */
#define P		(0)
#define S		(1<<0)	/* i.e. always serialize */
#define FD		(1<<1)	/* fd must be first arg: uses fd */
#define FILE_READ	(FD|(1<<2))	/* reads  data via fd */
#define FILE_WRITE	(FD|(1<<3))	/* writes data via fd */
#define FDTABLE		(1<<4)	/* modifies fd table */
#define FSINFO_READ	(1<<5)	/* uses     fs info */
#define FSINFO_WRITE	(1<<6)	/* modifies fs info */
#define MM		(1<<7)
/* sleep options */
#define NOSLEEP		(1<<15)

/*
static uint16_t syscall_info_table[__NR_syscall_max] = {
#include <linux/syscallinfo.h>
};
*/

#include "ft_common.h"

// CTU Constants
#define ENABLE_CTU 0
#define ENABLE_CTU_CMP 1
#define ENABLE_CTU_LOCKSTEP 0

#define MAX_CTU_RETRIES 4

#define FT_CTU_VERBOSE 0

#if FT_CTU_VERBOSE
#define FTPRINTK(...) printk(__VA_ARGS__)
#else
#define FTPRINTK(...) do {} while (0)
#endif

hash_table_t *syscall_hash;

static struct workqueue_struct *ft_syscall_info_wq;

struct wait_syscall {
	struct task_struct *task;
	int populated;
	char *extra_key;
	void *private;
};

struct send_syscall_work {
	struct work_struct work;
	u64 time;
	struct ft_pop_rep *replica_group;	//to know secondary replicas to whom send the msg
	struct ft_pid sender;
	int syscall_id;		//syscall id for that ft_pid replica
	unsigned int private_data_size;	//size of the private data of the syscall
	char *private;
};

struct syscall_msg {
	struct pcn_kmsg_hdr header;
	/*the following is pid_t linearized */
	struct ft_pop_rep_id ft_pop_id;
	int level;
	int id_array[MAX_GENERATION_LENGTH];

	int syscall_id;
	unsigned int syscall_info_size;

	int extra_key_size;

	/*this must be the last field of the struct */
	char data;		/*contains syscall_info + extra_key */
};

static int
create_syscall_msg(struct ft_pop_rep_id *primary_ft_pop_id, int primary_level,
		   int *primary_id_array, int syscall_id, char *syscall_info,
		   unsigned int syscall_info_size, char *extra_key,
		   int extra_key_size, struct syscall_msg **message,
		   int *msg_size)
{
	struct syscall_msg *msg;
	int size;
	char *variable_data;

	size = sizeof (*msg) + syscall_info_size + extra_key_size;
	msg = kmalloc(size, GFP_KERNEL);
	memset(msg, 0, size);
	if (!msg)
		return -ENOMEM;

	msg->header.type = PCN_KMSG_TYPE_FT_SYSCALL_INFO;
	msg->header.prio = PCN_KMSG_PRIO_HIGH;

	msg->ft_pop_id = *primary_ft_pop_id;
	msg->level = primary_level;

	if (primary_level)
		memcpy(msg->id_array, primary_id_array,
		       primary_level * sizeof (int));

	msg->syscall_id = syscall_id;
	msg->syscall_info_size = syscall_info_size;
	msg->extra_key_size = extra_key_size;

	variable_data = &msg->data;

	if (syscall_info_size) {
		memcpy(variable_data, syscall_info, syscall_info_size);
	}

	variable_data = &msg->data + syscall_info_size;
	if (extra_key_size) {
		memcpy(variable_data, extra_key, extra_key_size);
	}

	*message = msg;
	*msg_size = size;

	return 0;
}

extern atomic64_t global_sysmsg_cnt;
static void
send_syscall_info_to_secondary_replicas(struct ft_pop_rep *replica_group,
					struct ft_pop_rep_id *primary_ft_pop_id,
					int primary_level,
					int *primary_id_array, int syscall_id,
					char *syscall_info,
					unsigned int syscall_info_size,
					char *extra_key,
					unsigned int extra_key_size)
{
	struct syscall_msg *msg;
	int msg_size;
	int ret;

	atomic64_inc(&global_sysmsg_cnt);
	ret =
	    create_syscall_msg(primary_ft_pop_id, primary_level,
			       primary_id_array, syscall_id, syscall_info,
			       syscall_info_size, extra_key, extra_key_size,
			       &msg, &msg_size);
	if (ret)
		return;

	send_to_all_secondary_replicas(replica_group,
				       (struct pcn_kmsg_long_message *) msg,
				       msg_size);

	kfree(msg);
}

//this is a workqueue
static void
send_syscall_info_to_secondary_replicas_from_work(struct work_struct *work)
{
	struct send_syscall_work *my_work = (struct send_syscall_work *) work;

	send_syscall_info_to_secondary_replicas(my_work->replica_group,
						&my_work->sender.ft_pop_id,
						my_work->sender.level,
						my_work->sender.id_array,
						my_work->syscall_id,
						my_work->private,
						my_work->private_data_size,
						NULL, 0);

	put_ft_pop_rep(my_work->replica_group);

	kfree(my_work->private);

	//ft_end_time(&my_work->time);
	//ft_update_time(&my_work->time, TIME_SEND_SYCALL);

	kfree(my_work);

}

/* Supposed to be called by a primary replica to send syscall info to its secondary replicas.
 * Data sent is stored in @syscall_info and it is of @syscall_info_size bytes.
 * A copy is made so data can be free after the call.
 * The current thread will be used to send the data.
 */
void
ft_send_syscall_info(struct ft_pop_rep *replica_group,
		     struct ft_pid *primary_pid, int syscall_id,
		     char *syscall_info, unsigned int syscall_info_size)
{
	u64 time;
	char *key;

	ft_start_time(&time);

	// For debugging
	/*
	   key = ft_syscall_get_key_from_ft_pid(primary_pid, syscall_id);
	   trace_printk("sending %s in %d\n", key, current->current_syscall);
	   kfree(key);
	 */

	send_syscall_info_to_secondary_replicas(replica_group,
						&primary_pid->ft_pop_id,
						primary_pid->level,
						primary_pid->id_array,
						syscall_id, syscall_info,
						syscall_info_size, NULL, 0);

	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_SEND_SYCALL);
}

/* Supposed to be called by a primary replica to send syscall info to its secondary replicas.
 * Data sent is stored in @syscall_info and it is of @syscall_info_size bytes.
 * A copy is made so data can be free after the call.
 * The current thread will be used to send the data.
 * It can provide and extra key to identify this syscall.
 */
void
ft_send_syscall_info_extra_key(struct ft_pop_rep *replica_group,
			       struct ft_pid *primary_pid, int syscall_id,
			       char *syscall_info,
			       unsigned int syscall_info_size, char *extra_key,
			       unsigned int extra_key_size)
{
	u64 time;

	ft_start_time(&time);

	send_syscall_info_to_secondary_replicas(replica_group,
						&primary_pid->ft_pop_id,
						primary_pid->level,
						primary_pid->id_array,
						syscall_id, syscall_info,
						syscall_info_size, extra_key,
						extra_key_size);

	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_SEND_SYCALL);
}

/* As for ft_send_syscall_info, but a worker thread will be used to send the data.
 * Also in this case a copy of the data will be made, so it is possible to free @syscall_info
 * after the call.
 */
void
ft_send_syscall_info_from_work(struct ft_pop_rep *replica_group,
			       struct ft_pid *primary_pid, int syscall_id,
			       char *syscall_info,
			       unsigned int syscall_info_size)
{
	struct send_syscall_work *work;
	u64 time = 0;

	//ft_start_time(&time);

	work = kmalloc(sizeof (*work), GFP_KERNEL);
	if (!work)
		return;

	get_ft_pop_rep(replica_group);
	work->replica_group = replica_group;

	work->sender = *primary_pid;

	/* Do a copy of syscall_info */
	work->private_data_size = syscall_info_size;
	if (syscall_info_size) {
		work->private = kmalloc(syscall_info_size, GFP_KERNEL);
		if (!work->private) {
			kfree(work);
			return;
		}
		memcpy(work->private, syscall_info, syscall_info_size);
	}
	work->syscall_id = syscall_id;
	work->time = time;

	INIT_WORK((struct work_struct *) work,
		  send_syscall_info_to_secondary_replicas_from_work);

	queue_work(ft_syscall_info_wq, (struct work_struct *) work);

	FTPRINTK("%s work queued\n", __func__);

	return;

}

/* Supposed to be called by primary after secondary replicas to get syscall data sent by the primary replica before failing if any.
 * The data returned is the one identified by the ft_pid of the replica and the syscall_id.
 */
void *
ft_get_pending_syscall_info(struct ft_pid *pri_after_sec, int id_syscall)
{
	struct wait_syscall *present_info = NULL;
	char *key;
	void *ret = NULL;

	FTPRINTK("%s called from pid %s\n", __func__, current->pid);

	key = ft_syscall_get_key_from_ft_pid(pri_after_sec, id_syscall);
	if (!key)
		return ERR_PTR(-ENOMEM);

	present_info = ft_syscall_hash_remove(key);

	if (present_info) {
		ret = present_info->private;
		if (present_info->extra_key)
			kfree(present_info->extra_key);

		kfree(present_info);
	}

	kfree(key);

	return ret;
}

/* Supposed to be called by secondary replicas to wait for syscall data sent by the primary replica.
 * The data returned is the one identified by the ft_pid of the replica and the syscall_id.
 * It may put the current thread to sleep.
 * extra_key will be added as info while sleeping, DO NOT free it!
 * NOTE: do not try to put more than one thread to sleep for the same data, it won't work. This is
 * designed to allow only the secondary replica itself to sleep while waiting the data from its primary.
 */
void *
ft_wait_for_syscall_info_extra_key(struct ft_pid *secondary, int id_syscall,
				   char *extra_key)
{
	struct wait_syscall *wait_info;
	struct wait_syscall *present_info = NULL;
	char *key;
	int free_key = 0;
	void *ret = NULL;
	u64 time;

	ft_start_time(&time);

	//FTPRINTK("%s called from pid %d\n", __func__, current->pid);

	key = ft_syscall_get_key_from_ft_pid(secondary, id_syscall);
	if (!key)
		return ERR_PTR(-ENOMEM);

	wait_info = kmalloc(sizeof (*wait_info), GFP_ATOMIC);
	if (!wait_info)
		return ERR_PTR(-ENOMEM);

	wait_info->task = current;
	wait_info->populated = 0;
	wait_info->private = NULL;
	wait_info->extra_key = extra_key;

	if ((present_info =
	     ((struct wait_syscall *)
	      ft_syscall_hash_add(key, (void *) wait_info)))) {
		//FTPRINTK("%s data present, no need to wait\n", __func__);

		kfree(extra_key);
		kfree(wait_info);
		free_key = 1;
		goto copy;
	} else {
		FTPRINTK("%s: pid %d going to wait for data\n", __func__,
			 current->pid);

		present_info = wait_info;
        int i = 0;
		while (present_info->populated == 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (present_info->populated == 0) ;
			schedule();
			set_current_state(TASK_RUNNING);
            if (i > 200) {
                printk("%s timeout\n", __func__);
                return -EFAULT;
            }
            i++;
		}

		//FTPRINTK("%s: data arrived for pid %d \n", __func__, current->pid);
	}

      copy:if (present_info->populated != 1) {
		printk
		    ("%s ERROR, entry present in syscall hash but not populated\n",
		     __func__);
		ret = ERR_PTR(-EFAULT);
		goto out;
	}

	ret = present_info->private;

      out:
	ft_syscall_hash_remove(key);
	if (free_key)
		kfree(key);
	if (present_info->extra_key)
		kfree(present_info->extra_key);
	kfree(present_info);

	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_RCV_SYSCALL);

	return ret;

}

/* Supposed to be called by secondary replicas to wait for syscall data sent by the primary replica.
 * The data returned is the one identified by the ft_pid of the replica and the syscall_id.
 * It may put the current thread to sleep.
 * NOTE: do not try to put more than one thread to sleep for the same data, it won't work. This is
 * designed to allow only the secondary replica itself to sleep while waiting the data from its primary.
 */
void *
ft_wait_for_syscall_info(struct ft_pid *secondary, int id_syscall)
{
	struct wait_syscall *wait_info;
	struct wait_syscall *present_info = NULL;
	char *key;
	int free_key = 0;
	void *ret = NULL;
	u64 time;

	ft_start_time(&time);

	//FTPRINTK("%s called from pid %s\n", __func__, current->pid);

	key = ft_syscall_get_key_from_ft_pid(secondary, id_syscall);
	if (!key)
		return ERR_PTR(-ENOMEM);

	wait_info = kmalloc(sizeof (*wait_info), GFP_ATOMIC);
	if (!wait_info)
		return ERR_PTR(-ENOMEM);

	wait_info->task = current;
	wait_info->populated = 0;
	wait_info->private = NULL;
	wait_info->extra_key = NULL;

	if ((present_info =
	     ((struct wait_syscall *)
	      ft_syscall_hash_add(key, (void *) wait_info)))) {
		//FTPRINTK("%s data present, no need to wait\n", __func__);

		kfree(wait_info);
		free_key = 1;
		goto copy;
	} else {
		//FTPRINTK("%s: pid %d going to wait for data\n", __func__, current->pid);

		present_info = wait_info;
        int i = 0;
		while (present_info->populated == 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (present_info->populated == 0) ;
			schedule();
			set_current_state(TASK_RUNNING);
            if (i > 200) {
                printk("%s timeout\n", __func__);
                return -EFAULT;
            }
            i++;

		}

		//FTPRINTK("%s: data arrived for pid %d \n", __func__, current->pid);
	}

      copy:if (present_info->populated != 1) {
		printk
		    ("%s ERROR, entry present in syscall hash but not populated\n",
		     __func__);
		ret = ERR_PTR(-EFAULT);
		goto out;
	}

	ret = present_info->private;

      out:
	ft_syscall_hash_remove(key);
	if (free_key)
		kfree(key);
	if (present_info->extra_key)
		kfree(present_info->extra_key);
	kfree(present_info);

	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_RCV_SYSCALL);

	return ret;

}

static int
ft_wake_up_primary_after_secondary(void)
{
	int ret = 0, i;
	list_entry_t *head, *app;
	struct wait_syscall *wait_info;
	int pending_syscalls = 0, woken_up = 0;

	spin_lock(&syscall_hash->spinlock);

	for (i = 0; i < syscall_hash->size; i++) {
		head = syscall_hash->table[i];
		if (head) {
			list_for_each_entry(app, &head->list, list) {
				if (!app->obj) {
					ret = -EFAULT;
					printk("ERROR: %s no obj field\n",
					       __func__);
					goto out;
				}
				pending_syscalls++;
				wait_info = (struct wait_syscall *) app->obj;
				if (wait_info->task
				    &&
				    ft_is_primary_after_secondary_replica
				    (wait_info->task)) {
					woken_up++;
					wait_info->populated = 1;
					wake_up_process(wait_info->task);
				}
			}
		}
	}

	trace_printk("pending syscalls %d of which woken up %d\n",
		     pending_syscalls, woken_up);
	printk("pending syscalls %d of which woken up %d\n", pending_syscalls,
	       woken_up);

      out:
	spin_unlock(&syscall_hash->spinlock);
	return ret;

}

static int
flush_sys_wq(void)
{
	drain_workqueue(ft_syscall_info_wq);
	return 0;
}

int
ft_are_syscall_extra_key_present(char *key)
{
	int ret = 0, i;
	list_entry_t *head, *app;
	struct wait_syscall *wait_info;

	spin_lock(&syscall_hash->spinlock);

	for (i = 0; i < syscall_hash->size; i++) {
		head = syscall_hash->table[i];
		if (head) {
			list_for_each_entry(app, &head->list, list) {
				if (!app->obj) {
					ret = -EFAULT;
					printk("ERROR: %s no obj field\n",
					       __func__);
					goto out;
				}
				wait_info = (struct wait_syscall *) app->obj;
				if (wait_info->extra_key
				    && (strcmp(wait_info->extra_key, key) ==
					0)) {
					ret++;
				}
			}
		}
	}

      out:
	spin_unlock(&syscall_hash->spinlock);
	return ret;

}

int
ft_check_and_set_syscall_extra_key_sleeping(char *key, int *extra_syscall)
{
	int ret = 0, i;
	list_entry_t *head, *app;
	struct wait_syscall *wait_info;

	spin_lock(&syscall_hash->spinlock);

	for (i = 0; i < syscall_hash->size; i++) {
		head = syscall_hash->table[i];
		if (head) {
			list_for_each_entry(app, &head->list, list) {
				if (!app->obj) {
					ret = -EFAULT;
					printk("ERROR: %s no obj field\n",
					       __func__);
					goto out;
				}
				wait_info = (struct wait_syscall *) app->obj;
				if (wait_info->extra_key
				    && (strcmp(wait_info->extra_key, key) ==
					0)) {
					//if wait_info->task is not NULL, a thread is waiting for the syscall
					if (wait_info->task)
						ret++;
				}
			}
		}
	}

      out:
	*extra_syscall = ret;
	spin_unlock(&syscall_hash->spinlock);
	return ret;

}

int
ft_check_and_set_syscall_extra_key(char *key, int *extra_syscall)
{
	int ret = 0, i;
	list_entry_t *head, *app;
	struct wait_syscall *wait_info;

	spin_lock(&syscall_hash->spinlock);

	for (i = 0; i < syscall_hash->size; i++) {
		head = syscall_hash->table[i];
		if (head) {
			list_for_each_entry(app, &head->list, list) {
				if (!app->obj) {
					ret = -EFAULT;
					printk("ERROR: %s no obj field\n",
					       __func__);
					goto out;
				}
				wait_info = (struct wait_syscall *) app->obj;
				if (wait_info->extra_key
				    && (strcmp(wait_info->extra_key, key) ==
					0)) {
					//count the one just sent from the primary
					if (wait_info->task)
						ret++;
				}
			}
		}
	}

      out:
	*extra_syscall = ret;
	spin_unlock(&syscall_hash->spinlock);
	return ret;

}

/* Flush any pending syscall info still to be consumed by worker thread
 * and wake up all primary_after_secondary replicas that are waiting for a syscall info.
 * NOTE: this is supposed to be called after update_replica_type_after_failure.
 */
int
flush_syscall_info(void)
{
	int ret;

	ret = flush_sys_wq();
	if (ret)
		return ret;

	ret = ft_wake_up_primary_after_secondary();

	return ret;
}

static int
handle_syscall_info_msg(struct pcn_kmsg_message *inc_msg)
{
	struct syscall_msg *msg = (struct syscall_msg *) inc_msg;
	struct wait_syscall *wait_info;
	struct wait_syscall *present_info = NULL;
	char *key;
	char *private;

	/* retrive variable data length field (syscall_info) */
	private = &msg->data;

	/* retrive key for this syscall in hash_table */
	key =
	    ft_syscall_get_key(&msg->ft_pop_id, msg->level, msg->id_array,
			       msg->syscall_id);
	if (!key)
		return -ENOMEM;

	/* create a wait_syscall struct.
	 * if nobody was already waiting for this syscall, this struct will be added
	 * on the hash table, otherwise the private field will be copied on the wait_syscall
	 * present on the hash table and this one will be discarded.
	 */
	wait_info = kmalloc(sizeof (*wait_info), GFP_ATOMIC);
	if (!wait_info)
		return -ENOMEM;

	if (msg->syscall_info_size) {
		wait_info->private =
		    kmalloc(msg->syscall_info_size, GFP_ATOMIC);
		if (!wait_info->private) {
			kfree(wait_info);
			return -ENOMEM;
		}
		memcpy(wait_info->private, private, msg->syscall_info_size);
	} else
		wait_info->private = NULL;

	if (msg->extra_key_size) {
		wait_info->extra_key = kmalloc(msg->extra_key_size, GFP_ATOMIC);
		if (!wait_info->extra_key) {
			if (wait_info->private)
				kfree(wait_info->private);
			kfree(wait_info);
			return -ENOMEM;
		}

		memcpy(wait_info->extra_key, private + msg->syscall_info_size,
		       msg->extra_key_size);
	} else
		wait_info->extra_key = NULL;

	wait_info->task = NULL;
	wait_info->populated = 1;

	if ((present_info =
	     ((struct wait_syscall *)
	      ft_syscall_hash_add(key, (void *) wait_info)))) {
		if (present_info->task == NULL) {
			printk("%s ERROR PRESENT INFO TASK IS NULL %d[%s]\n",
			       __func__, msg->syscall_id, key);

		} else {
			present_info->private = wait_info->private;
			present_info->populated = 1;
			wake_up_process(present_info->task);
		}

		kfree(key);
		if (wait_info->extra_key)
			kfree(wait_info->extra_key);
		kfree(wait_info);
	}

	pcn_kmsg_free_msg(msg);

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// bump stuff
///////////////////////////////////////////////////////////////////////////////

hash_table_t *tickbump_hash;

/*
 * Message structure for synchronizing bumps
 */
struct tick_bump_msg {
	struct pcn_kmsg_hdr header;
	struct ft_pop_rep_id ft_pop_id;
	int level;
	int id_array[MAX_GENERATION_LENGTH];
	int syscall_id;
	uint64_t prev_tick;
	uint64_t new_tick;
};

struct wait_bump_info {
	struct task_struct *task;
	uint64_t prev_tick;
	uint64_t new_tick;
	int populated;
};

char *
tickbump_get_key(struct ft_pop_rep_id *ft_pop_id, int level, int *id_array,
		 int id_syscall, uint64_t oldtick)
{
	char *string;
	const int size = 128;
	int pos, i;

	string = kmalloc(size, GFP_ATOMIC);
	if (!string) {
		printk("%s impossible to kmalloc\n", __func__);
		return NULL;
	}

	pos =
	    snprintf(string, size, "%llu %d %d %d", oldtick, ft_pop_id->kernel,
		     ft_pop_id->id, level);
	if (pos >= size)
		goto out_clean;

	if (level) {
		for (i = 0; i < level; i++) {
			pos =
			    pos + snprintf(&string[pos], size - pos, " %d",
					   id_array[i]);
			if (pos >= size)
				goto out_clean;
		}
	}

	pos =
	    pos + snprintf(&string[pos], size - pos, " %d%c", id_syscall, '\0');
	if (pos >= size)
		goto out_clean;

	return string;

      out_clean:
	kfree(string);
	printk("%s: buffer size too small\n", __func__);
	return NULL;
}

static int
handle_bump_info_msg(struct pcn_kmsg_message *inc_msg)
{
	struct tick_bump_msg *msg = (struct tick_bump_msg *) inc_msg;
	struct wait_bump_info *wait_info;
	struct wait_bump_info *present_info;
	char *key;

	//trace_printk("got msg %d %d %lld\n", msg->level, msg->syscall_id, msg->prev_tick);
	key =
	    tickbump_get_key(&msg->ft_pop_id, msg->level, msg->id_array,
			     msg->syscall_id, msg->prev_tick);
	if (!key)
		return -ENOMEM;

	wait_info = kmalloc(sizeof (struct wait_bump_info), GFP_ATOMIC);
	wait_info->task = NULL;
	wait_info->populated = 1;
	wait_info->prev_tick = msg->prev_tick;
	wait_info->new_tick = msg->new_tick;

	//trace_printk("%s\n", key);
	if ((present_info =
	     (struct wait_bump_info *) hash_add(tickbump_hash, key,
						(void *) wait_info))) {
		if (present_info->task == NULL) {
			printk("%s ERROR PRESENT INFO TASK IS NULL %d[%s]\n",
			       __func__, msg->syscall_id, key);
		} else {
			present_info->prev_tick = wait_info->prev_tick;
			present_info->new_tick = wait_info->new_tick;
			present_info->populated = 1;
			wake_up_process(present_info->task);
		}

		kfree(key);
		kfree(wait_info);
	}

	pcn_kmsg_free_msg(msg);

	return 0;
}

static uint64_t
wait_for_bump_info(struct task_struct *task)
{
	struct wait_bump_info *wait_info;
	struct wait_bump_info *present_info;
	char *key;
	uint64_t ret = -1;
	int free_key = 0;

	key =
	    tickbump_get_key(&task->ft_pid.ft_pop_id, task->ft_pid.level,
			     task->ft_pid.id_array, task->id_syscall,
			     task->ft_det_tick);
	if (!key)
		return -1;
	//trace_printk("%d wait bump %s, on %d[%d]<%d>\n", task->pid, key, task->ft_det_tick, task->id_syscall, task->current_syscall);

	wait_info = kmalloc(sizeof (struct wait_bump_info), GFP_ATOMIC);
	wait_info->task = task;
	wait_info->populated = 0;
	wait_info->prev_tick = task->ft_det_tick;
	wait_info->new_tick = 0;

	if ((present_info =
	     ((struct wait_bump_info *)
	      hash_add(tickbump_hash, key, (void *) wait_info)))) {
		kfree(wait_info);
		free_key = 1;
	} else {
		present_info = wait_info;
        int i = 0;
		while (present_info->populated == 0 && ft_is_secondary_replica(task)) {	// This is needed because during the recovery it might still be spinning on a bump
			if (present_info->populated == 0)
				schedule_timeout_interruptible(1);
            if (i > 200) {
                printk("%s timeout\n", __func__);
                return -EFAULT;
            }
            i++;
		}
	}
	ret = present_info->new_tick;

	hash_remove(tickbump_hash, key);
	if (free_key)
		kfree(key);

	kfree(present_info);
	return ret;
}

static uint64_t
get_pending_bump_info(struct task_struct *task)
{
	struct wait_bump_info *present_info;
	char *key;
	uint64_t ret = -1;

	key =
	    tickbump_get_key(&task->ft_pid.ft_pop_id, task->ft_pid.level,
			     task->ft_pid.id_array, task->id_syscall,
			     task->ft_det_tick);
	if (!key)
		return -1;

	present_info = hash_remove(tickbump_hash, key);

	if (present_info) {
		ret = present_info->new_tick;
		kfree(present_info);
	}

	kfree(key);

	return ret;
}

void
consume_pending_bump(struct task_struct *task)
{
	uint64_t new_tick;
	struct popcorn_namespace *ns;
	ns = task->nsproxy->pop_ns;

    int i = 0;
	while ((new_tick = get_pending_bump_info(task)) != -1) {
		spin_lock(&ns->task_list_lock);
		task->ft_det_tick = new_tick;
		update_token(ns);
		spin_unlock(&ns->task_list_lock);
        if (i > 200) {
            printk("%s timeout\n", __func__);
            return;
        }
        i++;
	}
}

#define LOCK_REPLICATION
void
wait_bump(struct task_struct *task)
{
	uint64_t new_tick;
	struct popcorn_namespace *ns;
	ns = task->nsproxy->pop_ns;

#ifdef LOCK_REPLICATION
	return 0;
#endif

	u64 time;
	ft_start_time(&time);
	/*
	 * Now the thread puts itself into sleep, until it receives a -1 bump on current tick.
	 * Because on the secondary every thread handles the bumps by itself, so no shepherd is needed.
	 */
    int i = 0;
	while ((new_tick = wait_for_bump_info(task)) != -1 && ft_is_secondary_replica(task)) {	// This is needed because during the recovery it might still be spinning on a bump
		spin_lock(&ns->task_list_lock);
		task->ft_det_tick = new_tick;
		update_token(ns);
		spin_unlock(&ns->task_list_lock);
        if (i > 200) {
            printk("%s timeout\n", __func__);
            return;
        }
        i++;
	}

	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_WAIT_BUMP);
}

extern atomic64_t global_tickmsg_cnt;
int
send_bump(struct task_struct *task, int id_syscall, uint64_t prev_tick,
	  uint64_t new_tick)
{
	struct tick_bump_msg *msg;

	atomic64_inc(&global_tickmsg_cnt);
#ifdef LOCK_REPLICATION
	return 0;
#endif

	u64 time;
	ft_start_time(&time);
	//trace_printk("%d is bumping %d to %d [%d]<%d>\n", task->pid, prev_tick, new_tick, id_syscall, task->current_syscall);
	msg = kmalloc(sizeof (struct tick_bump_msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->header.type = PCN_KMSG_TYPE_FT_TICKBUMP_INFO;
	msg->header.prio = PCN_KMSG_PRIO_HIGH;
	memcpy(&(msg->ft_pop_id), &(task->ft_pid.ft_pop_id),
	       sizeof (struct ft_pop_rep_id));
	msg->level = task->ft_pid.level;
	if (msg->level) {
		memcpy(msg->id_array, task->ft_pid.id_array,
		       msg->level * sizeof (int));
	} else {
		memset(msg->id_array, 0, msg->level * sizeof (int));
	}
	msg->syscall_id = id_syscall;
	msg->prev_tick = prev_tick;
	msg->new_tick = new_tick;
	send_to_all_secondary_replicas(task->ft_popcorn,
				       (struct pcn_kmsg_long_message *) msg,
				       sizeof (struct tick_bump_msg));
	kfree(msg);
	//trace_printk("%d done sending bump\n", task->pid);
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_SEND_BUMP);
	return 0;
}

#ifdef CONFIG_KMVX
///////////////////////////////////////////////////////////////////////////////
// copy_to_user (ctu) stuff (this is directly copied from the *_bump stuff
///////////////////////////////////////////////////////////////////////////////

hash_table_t *ctu_hash;
hash_table_t *cfu_hash;

struct ctu_msg {
	struct pcn_kmsg_hdr header;
	struct ft_pop_rep_id ft_pop_id;
	int level;
	int id_array[MAX_GENERATION_LENGTH];
	int syscall_id;
	int ctu_id;
	char is_cfu;
	unsigned int ctu_info_size;
	char data[];
};

struct wait_ctu_info {
	struct task_struct *task;
	int syscall_id;
	int ctu_id;
	char is_cfu;
	unsigned int ctu_info_size;
	void *private;
	int populated;
};

char *
ctu_get_key(struct ft_pop_rep_id *ft_pop_id, int level, int *id_array,
	    int id_syscall, int ctu_count)
{
	char *string;
	const int size = 128;
	int pos, i;

	string = kmalloc(size, GFP_ATOMIC);
	if (!string) {
		printk("%s impossible to kmalloc\n", __func__);
		return NULL;
	}

	pos =
	    snprintf(string, size, "%d %d %d %d", ctu_count, ft_pop_id->kernel,
		     ft_pop_id->id, level);
	if (pos >= size)
		goto out_clean;

	if (level) {
		for (i = 0; i < level; i++) {
			pos =
			    pos + snprintf(&string[pos], size - pos, " %d",
					   id_array[i]);
			if (pos >= size)
				goto out_clean;
		}
	}

	pos =
	    pos + snprintf(&string[pos], size - pos, " %d%c", id_syscall, '\0');
	if (pos >= size)
		goto out_clean;

	return string;

      out_clean:
	kfree(string);
	printk("%s: buffer size too small\n", __func__);
	return NULL;
}

static int
handle_ctu_info_msg(struct pcn_kmsg_message *inc_msg)
{
	struct ctu_msg *msg = (struct ctu_msg *) inc_msg;
	struct wait_ctu_info *wait_info;
	struct wait_ctu_info *present_info;
	char *key;

	//printk("got ctu info message\n");

	key =
	    ctu_get_key(&msg->ft_pop_id, msg->level, msg->id_array,
			msg->syscall_id, msg->ctu_id);
	if (!key)
		return -ENOMEM;

	wait_info = kmalloc(sizeof (struct wait_ctu_info), GFP_ATOMIC);	// todo convert in a cache pool
	if (!wait_info)
		printk("%s: ERROR cannot allocate memory for wait_info\n",
		       __func__);

	memset(wait_info, 0, sizeof (struct wait_ctu_info));
	wait_info->task = NULL;
	wait_info->populated = 1;
	wait_info->syscall_id = msg->syscall_id;
	wait_info->ctu_id = msg->ctu_id;
	wait_info->is_cfu = msg->is_cfu;
	wait_info->ctu_info_size = msg->ctu_info_size;
	if (wait_info->ctu_info_size) {
		wait_info->private =
		    kmalloc((wait_info->ctu_info_size), GFP_ATOMIC);
		if (!wait_info->private)
			printk
			    ("%s: ERROR cannot allocate memory for wait_info->private\n",
			     __func__);
		else
			memcpy(wait_info->private, msg->data,
			       wait_info->ctu_info_size);
	}
	mb();
	trace_printk
	    ("%s: wait_info task:%p(%d) populated:%d syscall_id:%d ctu_id:%d ctu_info_size:%d private:%p\n",
	     key, wait_info->task,
	     wait_info->task ? wait_info->task->current_syscall : -1,
	     wait_info->populated, wait_info->syscall_id, wait_info->ctu_id,
	     wait_info->ctu_info_size, wait_info->private);

	if ((present_info =
	     (struct wait_ctu_info *) hash_add(/*wait_info->is_cfu == 0 ? ctu_hash
					       : cfu_hash */ ctu_hash, key,
					       (void *) wait_info))) {

		if (IS_ERR(present_info)) {
			printk("%s ERROR PRESENT INFO hash_add error %d[%s]\n",
			       __func__, msg->syscall_id, key);
		} else {
			if (present_info->task == NULL) {
				printk
				    ("%s ERROR PRESENT INFO TASK IS NULL %d[%s]\n",
				     __func__, msg->syscall_id, key);
			} else {
				present_info->syscall_id =
				    wait_info->syscall_id;
				present_info->ctu_id = wait_info->ctu_id;
				present_info->ctu_info_size =
				    wait_info->ctu_info_size;
				present_info->private = wait_info->private;
				mb();
				present_info->populated = 1;
				wake_up_process(present_info->task);
			}
		}

		kfree(key);
		kfree(wait_info);
	}			// hash_add returns null when no entry with the same id found

	pcn_kmsg_free_msg(msg);
	//printk("done handle ctu info message\n");
	return 0;
}

static int
wait_for_ctu_info(struct task_struct *task, int *psyscall, int
		  *psize, char **pbuf, int is_cfu)
{
	struct wait_ctu_info *wait_info;
	struct wait_ctu_info *present_info;
	char *key;
	int ret = -1;
	int free_key = 0;

        //int sync_id = is_cfu == 1 ? task->id_cfu : task->id_ctu;
        int sync_id = task->id_ctu;

	//dump_stack();
	key = ctu_get_key(&task->ft_pid.ft_pop_id,
			  task->ft_pid.level, task->ft_pid.id_array,
			  /*task->id_syscall */ task->current_syscall,
			  sync_id);
	if (!key) {
		FTPRINTK("SEBASTIAN: wait_for_ctu_info return -1\n");
		return -1;
	}
	trace_printk("%d wait bump %s, on %d[%d]<%d>\n", task->pid, key,
		     task->ft_det_tick,	/*task->id_syscall */
		     task->current_syscall, task->current_syscall);
	wait_info = kmalloc(sizeof (struct wait_ctu_info), GFP_ATOMIC);
	memset(wait_info, 0, sizeof (struct wait_ctu_info));
	wait_info->task = task;
	wait_info->populated = 0;
	wait_info->syscall_id = /*task->id_syscall */ task->current_syscall;
	wait_info->ctu_id = sync_id;

	if ((present_info =
	     ((struct wait_ctu_info *)
	      hash_add(ctu_hash, key, (void *) wait_info)))) {
		if (present_info->syscall_id != wait_info->syscall_id)
			printk
			    ("%s: ERROR hash map content mismatch syscall_id %d %d\n",
			     __func__, present_info->syscall_id,
			     wait_info->syscall_id);
		if (present_info->ctu_id != wait_info->ctu_id)
			printk
			    ("%s: ERROR hash map content mismatch ctu_id %d %d\n",
			     __func__, present_info->ctu_id, wait_info->ctu_id);

		kfree(wait_info);
		free_key = 1;
	} else {
		present_info = wait_info;
	}

	int retries = 0;
	while (present_info->populated == 0 && ft_is_secondary_replica(task)) {	// This is needed because during the recovery it might still be spinning on a bump
		if (retries > MAX_CTU_RETRIES) {
			FTPRINTK("give up on wait_for_ctu. Max retries.\n");
			kfree(key);
			kfree(present_info);
			return -1;
		}
		if (present_info->populated == 0)
			schedule_timeout_interruptible(1);

		retries++;

	}
	//printk("DONE WAITING for ctu\n");
	trace_printk
	    ("%s: present_info task:%p(%d) populated:%d syscall_id:%d ctu_id:%d ctu_info_size:%d private:%p\n",
	     key, present_info->task,
	     present_info->task ? present_info->task->current_syscall : -1,
	     present_info->populated, present_info->syscall_id,
	     present_info->ctu_id, present_info->ctu_info_size,
	     present_info->private);

	ret = present_info->ctu_id;
	if (psyscall)
		*psyscall = present_info->syscall_id;
	if (psize)
		*psize = present_info->ctu_info_size;
	if (pbuf)
		*pbuf = present_info->private;
	mb();

	hash_remove(ctu_hash, key);
	if (free_key)
		kfree(key);

	kfree(present_info);
	return ret;
}

//Wen: this is only for recovery
static int
get_pending_ctu_info(struct task_struct *task)
{
	struct wait_ctu_info *present_info;
	char *key;
	int ret = -1;

	key = ctu_get_key(&task->ft_pid.ft_pop_id,
			  task->ft_pid.level, task->ft_pid.id_array,
			  /*task->id_syscall */ task->current_syscall,
			  task->id_ctu);
	if (!key)
		return -1;

	present_info = hash_remove(ctu_hash, key);

	if (present_info) {
		ret = present_info->ctu_id;
		kfree(present_info);
	}

	kfree(key);

	return ret;
}

//Wen: this is only for recovery
void
consume_pending_ctu(struct task_struct *task)
{
	int ctu_id;
	struct popcorn_namespace *ns;
	ns = task->nsproxy->pop_ns;

    int i = 0;
	while ((ctu_id = get_pending_ctu_info(task)) != -1) {
		spin_lock(&ns->task_list_lock);	// TODO I don't think I need this
		task->id_ctu = ctu_id;
		update_token(ns);	// TODO I don't think I need this
		spin_unlock(&ns->task_list_lock);	// TODO I don't think I need this
        if (i > 200) {
            printk("%s timeout\n", __func__);
            return;
        }
        i++;
	}
}

#if 0
//Wen: this is only for recovery
#define LOCK_REPLICATION
void
wait_ctu(struct task_struct *task)
{
	int ctu_id;
	struct popcorn_namespace *ns;
	ns = task->nsproxy->pop_ns;

	u64 time;
	ft_start_time(&time);
	/*
	 * Now the thread puts itself into sleep, until it receives a -1 bump on current tick.
	 * Because on the secondary every thread handles the bumps by itself, so no shepherd is needed.
	 */
	while ((ctu_id = wait_for_ctu_info(task)) != -1 && ft_is_secondary_replica(task)) {	// This is needed because during the recovery it might still be spinning on a bump
		spin_lock(&ns->task_list_lock);	// TODO I don't think I need this
		task->id_ctu = ctu_id;
		update_token(ns);	// TODO I don't think I need this
		spin_unlock(&ns->task_list_lock);	// TODO I don't think I need this
	}

	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_WAIT_BUMP);
}
#endif

//TODO increment the ctu_id for the thread (it is per thread so no issues about the multithreding)
extern atomic64_t global_ctu_cnt;
int
send_ctu(struct task_struct *task, int id_syscall, int id_ctu, int size_ctu,
	 char *buffer, int is_cfu)
{
	struct ctu_msg *msg;

	u64 time;
	ft_start_time(&time);

	atomic64_inc(&global_ctu_cnt);

	int msg_size = sizeof (struct ctu_msg) + size_ctu;
	msg = kmalloc(msg_size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->header.type = PCN_KMSG_TYPE_FT_CTU_INFO;
	msg->header.prio = PCN_KMSG_PRIO_HIGH;

	memcpy(&(msg->ft_pop_id), &(task->ft_pid.ft_pop_id),
	       sizeof (struct ft_pop_rep_id));
	msg->level = task->ft_pid.level;
	if (msg->level) {
		memcpy(msg->id_array, task->ft_pid.id_array,
		       msg->level * sizeof (int));
	} else {
		memset(msg->id_array, 0, msg->level * sizeof (int));
	}

	msg->syscall_id = id_syscall;
	msg->ctu_id = id_ctu;
	msg->is_cfu = is_cfu;
	msg->ctu_info_size = size_ctu;

	if (size_ctu)
		memcpy(msg->data, buffer, size_ctu);
	mb();
	trace_printk
	    ("ctu_msg:%d size_ctu:%d level:%d array@ syscall_id:%d ctu_id:%d data:0x%lx\n",
	     sizeof (struct ctu_msg), size_ctu, msg->level, msg->syscall_id,
	     msg->ctu_id, *(unsigned long *) &(msg->data));

	send_to_all_secondary_replicas(task->ft_popcorn,
				       (struct pcn_kmsg_long_message *) msg,
				       msg_size);
	kfree(msg);
	//trace_printk("%d done sending bump\n", task->pid);
	ft_end_time(&time);
	ft_update_time(&time, FT_TIME_SEND_CTU);
	return 0;
}

/**
 * Send CTU check acknowledgement
 */
void
ack_ctu_check(struct task_struct *task, int id_ctu)
{
	struct ctu_msg *msg;

	FTPRINTK("%s START\n", __func__);
	int msg_size = sizeof (struct ctu_msg);
	msg = kmalloc(msg_size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	msg->header.type = PCN_KMSG_TYPE_FT_CTU_ACK;
	msg->header.prio = PCN_KMSG_PRIO_HIGH;
	msg->ctu_id = id_ctu;
	msg->ft_pop_id = current->ft_pid.ft_pop_id;

	FTPRINTK("SENDING CTU ACK PID: %d\n", current->ft_pid.ft_pop_id.id);
	send_to_primary(task->ft_popcorn, msg, msg_size);
	kfree(msg);
	FTPRINTK("SENT CTU ACK\n");
}

hash_table_t *ctu_ack_table;
/**
 * Handler for CTU acknowledgement messages
 */
static int
handle_ctu_ack_msg(struct pcn_kmsg_message *msg)
{
	struct ctu_msg *ctu_m = (struct ctu_msg *) msg;
	if (!ctu_m)
		return -1;
	char *buffer;
	buffer = kmalloc(33, GFP_KERNEL);
	snprintf(buffer, 33, "%d", ctu_m->ft_pop_id.id);
	int *val = kmalloc(sizeof (int), GFP_KERNEL);
	if (!val)
		return -1;
	*val = ctu_m->ctu_id;
	FTPRINTK("GOT CTU ACK (%d) PID:%d\n", *val, ctu_m->ft_pop_id.id);

	int *r = (int *) hash_add(ctu_ack_table, buffer, val);
	if (r && *r <= *val) {
		FTPRINTK("CHNG %d -> %d\n", *r, *val);
		//spin_lock(&ctu_ack_table->spinlock); TODO: Own lock
		*r = *val;
		//spin_unlock(&ctu_ack_table->spinlock);
		kfree(val);
	}

	// Debug check that hash exists
	int *val2;
	val2 = (int *) hash_lookup(ctu_ack_table, buffer);

	pcn_kmsg_free_msg(msg);
	FTPRINTK("VAL IS %d\n", val2 == NULL ? NULL : *val2);
	return 0;
}

/**
 * Wait for a CTU check acknowledgement. Gives up after MAX_CTU_RETRIES retries.
 * Returns -1 on failure.
 */
int
wait_for_ctu_ack(int ctu_cnt)
{
	int *val;
	char buffer[33];
	int retries = 0;

	snprintf(buffer, 33, "%d", current->ft_pid.ft_pop_id.id);
	val = (int *) hash_lookup(ctu_ack_table, buffer);
	FTPRINTK("WAITING FOR PID: %s CTU ACK %d. VAL: %d\n", buffer, ctu_cnt,
		 val == NULL ? NULL : *val);

	while (retries < MAX_CTU_RETRIES) {
		val = (int *) hash_lookup(ctu_ack_table, buffer);
		if (val && *val >= ctu_cnt) {
			break;
		}
		schedule_timeout_interruptible(1);
		retries++;
	}

	FTPRINTK("%s: done waiting (%d iterations) PID:%d VAL:%p\n", __func__,
		 retries, current->ft_pid.ft_pop_id.id, val);
	// Return -1 if too many retries.
	if (retries >= MAX_CTU_RETRIES)
		return -1;
	return 0;
}
void
ft_copy_from_user(void *to, const void __user *from, unsigned long size)
{
	if (!ENABLE_CTU)
		return;

	current->id_ctu++;
	if (!should_check(current->pid, current->current_syscall, CFU_FLAG)) {
	   return;
	}

	if (ft_is_primary_replica(current)) {
	    // Wait for replica
	   char *buf = 0;
	   int remote_syscall, remote_size, __ret, dump = 0;
	   int ctu = 0;
	   ctu = wait_for_ctu_info(current, &remote_syscall, &remote_size, &buf, 1);
	   // TODO: refactor into check function
	   if (ctu < 0) {
		   // Decrement id_ctu if there is a failure
		   //current->id_ctu--;
		   goto ctu_end;
	   }

	   if (ctu != current->id_ctu) {
		   FTPRINTK
			   ("%s: %d FOUND DIFFERENCE ctu %d current->ctu %d\n",
			    __func__, remote_syscall, ctu, current->id_ctu);
		   dump++;
	   }
	   if (remote_syscall !=
			   /*current->id_syscall */ current->current_syscall) {
		   FTPRINTK
			   ("%s: FOUND DIFFERENCE syscall %d current->syscall %d\n",
			    __func__, remote_syscall, /*current->id_syscall */
			    current->current_syscall);
		   dump++;
	   }
	   if (remote_size != size) {
		   FTPRINTK
			   ("%s: %d FOUND DIFFERENCE size %d ctu_size %d\n",
			    __func__, remote_syscall, remote_size, size);
		   dump++;
	   }
	   if (((unsigned long) buf < 0x1000) || !size)
		   FTPRINTK
			   ("%s: %d WARNING buf(%p=%p) or size(%d=%d) zero\n",
			    __func__, remote_syscall, buf, from, remote_size,
			    size);
	   else if (ENABLE_CTU_CMP
			   && (__ret =
				   memcmp(buf, from,
					   (size >
					    remote_size) ? remote_size : size))) {
		   int i;
		   char *bp1, *bp2;
		   for (bp1 = buf, bp2 = from, i = 0;
				   *bp1 == *bp2; bp1++, bp2++, i++) ;

		   FTPRINTK
			   ("%s: %d FOUND DIFFERENCE buf -- memcmp returned %d [%d] (%s, %s)\n",
			    __func__, remote_syscall, __ret, i,
			    ((char *) buf + i), ((char *) from + i));

		   dump++;
	   }
ctu_end:
	   if (FT_CTU_VERBOSE && dump)
		   dump_stack();

	   if (buf)
		   kfree(buf);
	} else if (ft_is_secondary_replica(current)) {
		char *buf = 0;
		int _ret = send_ctu(current,
				current->current_syscall, current->id_ctu,
				size, from, 1);


	}
}

/* NOTE it is called ft_copy_to_user but it is not supposed to be used for ft
 * (note that there is no ft_is_primary_after_secondary_replica () handling
 */
	void
ft_copy_to_user(const void *src, unsigned size)
{
	if (!ENABLE_CTU)
		return;
	if (!should_check(current->pid, current->current_syscall, CTU_FLAG)) {
	   return;
	}
	/*if (current->current_syscall == __NR_getrlimit ||
	  syscall_info_table[current->current_syscall] & FSINFO_READ ||
	  current->current_syscall == __NR_gettimeofday ||
	  current->current_syscall == __NR_epoll_wait ||
	  current->current_syscall == __NR_poll ||
	  current->current_syscall == __NR_accept ||
	  current->current_syscall == __NR_accept4 ||
	  current->current_syscall == __NR_bind ||
	  current->current_syscall == __NR_listen ||
	  current->current_syscall == __NR_rt_sigaction) {

	  return;
	  }
	 */
	/*
	   if (!(current->current_syscall == __NR_gettimeofday ||
	   current->current_syscall == __NR_epoll_wait ||
	   current->current_syscall == __NR_poll ||
	   current->current_syscall == __NR_write ||
	   current->current_syscall == __NR_read ||
	// Start NET
	current->current_syscall == __NR_socket ||
	current->current_syscall == __NR_bind ||
	current->current_syscall == __NR_connect ||
	current->current_syscall == __NR_listen ||
	current->current_syscall == __NR_accept ||
	current->current_syscall == __NR_getsockname ||
	current->current_syscall == __NR_getpeername ||
	current->current_syscall == __NR_socketpair ||
	current->current_syscall == __NR_sendto ||
	current->current_syscall == __NR_recvfrom||
	current->current_syscall == __NR_shutdown||
	current->current_syscall == __NR_setsockopt||
	current->current_syscall == __NR_getsockopt	||
	current->current_syscall == __NR_sendmsg ||
	current->current_syscall == __NR_recvmsg ||
	current->current_syscall == __NR_accept4
	)) {
	return;
	}
	 */
	current->id_ctu++;

	/* The primary sends the copy_to_user src buffer to the replicas */
	if (ft_is_primary_replica(current)) {
		if (current->id_ctu % 100 == 0) {
			print_ft_time_breakdown();
		}
		if (current->id_ctu % 10 == 1) {
			wait_for_ctu_ack(current->id_ctu);
			// Decrement id_ctu if there is a failure
		}
		trace_printk("ft_is_primary_replica REPLICATING\n");
		if (is_there_any_secondary_replica(current->ft_popcorn)) {
			trace_printk("REPLICATING there is secondary\n");
			int _ret =
				send_ctu(current, /*current->id_syscall */
						current->current_syscall, current->id_ctu,
						size, src, 0);

			if (_ret)
				printk
					("%s: ERROR cannot send message to secondary _ret %d\n",
					 __func__, _ret);

#if ENABLE_CTU_LOCKSTEP
			if (wait_for_ctu_ack(current->id_ctu) < 0) {
				// Decrement id_ctu if there is a failure
				current->id_ctu--;
				FTPRINTK("LOCKSTEP timeout\n");
			}
#endif
		}
	}
	/* The secondary wait to receive the copy_to_user buffer from the primary
	 * and compares the buffer content
	 */
	else if (ft_is_secondary_replica(current)) {
		char *buf = 0;
		int remote_syscall, remote_size, __ret, dump = 0;
		int ctu = 0;

		if (current->id_ctu % 10 == 1) {
			ack_ctu_check(current, current->id_ctu);
		}

		ctu =
			wait_for_ctu_info(current, &remote_syscall, &remote_size,
					&buf, 0);
		if (ctu < 0) {
			// Decrement id_ctu if there is a failure
			//current->id_ctu--;
			goto ctu_end;
		}

		if (ctu != current->id_ctu) {
			FTPRINTK
				("%s: %d FOUND DIFFERENCE ctu %d current->ctu %d\n",
				 __func__, remote_syscall, ctu, current->id_ctu);
			dump++;
		}
		if (remote_syscall !=
				/*current->id_syscall */ current->current_syscall) {
			FTPRINTK
				("%s: FOUND DIFFERENCE syscall %d current->syscall %d\n",
				 __func__, remote_syscall, /*current->id_syscall */
				 current->current_syscall);
			dump++;
		}
		if (remote_size != size) {
			FTPRINTK
				("%s: %d FOUND DIFFERENCE size %d ctu_size %d\n",
				 __func__, remote_syscall, remote_size, size);
			dump++;
		}
		if (((unsigned long) buf < 0x1000) || !size)
			FTPRINTK
				("%s: %d WARNING buf(%p=%p) or size(%d=%d) zero\n",
				 __func__, remote_syscall, buf, src, remote_size,
				 size);
		else if (ENABLE_CTU_CMP
				&& (__ret =
					memcmp(buf, src,
						(size >
						 remote_size) ? remote_size : size))) {
			int i;
			char *bp1, *bp2;
			for (bp1 = buf, bp2 = src, i = 0;
					*bp1 == *bp2; bp1++, bp2++, i++) ;

			FTPRINTK
				("%s: %d FOUND DIFFERENCE buf -- memcmp returned %d [%d] (%s, %s)\n",
				 __func__, remote_syscall, __ret, i,
				 ((char *) buf + i), ((char *) src + i));

			dump++;
		}
ctu_end:
		if (FT_CTU_VERBOSE && dump)
			dump_stack();

		if (buf)
			kfree(buf);
#if ENABLE_CTU_LOCKSTEP
		ack_ctu_check(current, current->id_ctu);
#endif
	}
}

EXPORT_SYMBOL(ft_copy_to_user);
EXPORT_SYMBOL(ft_copy_from_user);
#endif				/* CONFIG_KMVX */

///////////////////////////////////////////////////////////////////////////////
// syscall management
///////////////////////////////////////////////////////////////////////////////

#ifdef TRACE_THIS
//trace_printk("%s Syscall %d (sycall id %d) on pid %d tic %u\n", __func__, current->current_syscall, current->id_syscall, current->pid, current->ft_det_tick);
//trace_printk("%s Syscall %d (sycall id %d) on pid %d tic %u\n", __func__, regs->orig_ax, current->id_syscall, current->pid, current->ft_det_tick);
#define TRACE_SYSCALL_HOOK(task, regs) \
	if ( ft_is_replicated(task) ) \
trace_printk("%d[%d] syscall %d<%d>\n", \
		task->pid, task->ft_det_tick, \
		regs ? regs->orig_ax : 0, task->id_syscall);
#else
#define TRACE_SYSCALL_HOOK(task, regs)
#endif

/*
 * System call number is in orig_ax
 * Only increment the system call counter if we see one of the synchronized system calls.
 *
 * Some socket system calls are handled inside the implementation:
 * __NR_read, __NR_sendto, __NR_sendmsg, __NR_recvfrom, __NR_recvmsg, __NR_write
 * Because we don't want non-socket read & write to be tracked.
 */
	long
syscall_hook_enter(struct pt_regs *regs)
{
	current->current_syscall = regs->orig_ax;
	current->bumped = -1;
	struct popcorn_namespace *ns;

	TRACE_SYSCALL_HOOK(current, regs);

	STATISTICS_SYSCALL_ENTER(current);

	// TODO: orgnize those syscalls in a better way, avoid this tidious if conditions
	if (ft_is_replicated(current) &&
			(current->current_syscall == __NR_gettimeofday ||
			 current->current_syscall == __NR_epoll_wait ||
			 current->current_syscall == __NR_time ||
			 current->current_syscall == __NR_poll ||
			 current->current_syscall == __NR_accept ||
			 current->current_syscall == __NR_accept4 ||
			 current->current_syscall == __NR_bind ||
			 current->current_syscall == __NR_listen)) {
		ns = current->nsproxy->pop_ns;
		spin_lock(&ns->task_list_lock);
		current->id_syscall++;
		current->bumped = 0;
		spin_unlock(&ns->task_list_lock);

		if (ft_is_secondary_replica(current)) {
			wait_bump(current);
		} else if (ft_is_primary_after_secondary_replica(current)) {
			consume_pending_bump(current);
		}
	}

	return regs->orig_ax;
}

// the following code was in syscall_hook_exit(struct pt_regs * regs)
/*
 *if (ft_is_primary_replica(current)) {
 *        // Wake up the other guy
 *        spin_lock_irqsave(&current->nsproxy->pop_ns->task_list_lock, flags);
 *        bump = current->ft_det_tick;
 *        id_syscall = current->id_syscall;
 *        current->bumped = 1;
 *        spin_unlock_irqrestore(&current->nsproxy->pop_ns->task_list_lock, flags);
 *        send_bump(current, id_syscall, bump, -1);
 *    }
 */
/*
 * This means the syscall is wrapped inside a det section, however the syscall may
 * or may not go to sleep:
 * 1. The syscall returns from a sleeping state
 * 2. The syscall didn't get into sleep (Like the read from secondary)
 * Either case, this syscall should go back to wait for its token
 *
 * Alright futex is handled inside the do_futex.
 */
/*
 *spin_lock_irqsave(&current->nsproxy->pop_ns->task_list_lock, flags);
 *if (current->ft_det_state == FT_DET_SLEEP_SYSCALL ||
 *        current->ft_det_state == FT_DET_ACTIVE) {
 *    spin_unlock_irqrestore(&current->nsproxy->pop_ns->task_list_lock, flags);
 *    det_wake_up(current);
 *} else {
 *    spin_unlock_irqrestore(&current->nsproxy->pop_ns->task_list_lock, flags);
 *}
 */

	void
syscall_hook_exit(struct pt_regs *regs)
{
	uint64_t bump = 0;
	int id_syscall = 0;
	unsigned long flags;

	if (ft_is_replicated(current) &&
			(current->current_syscall == __NR_gettimeofday ||
			 current->current_syscall == __NR_epoll_wait ||
			 current->current_syscall == __NR_time ||
			 current->current_syscall == __NR_poll ||
			 current->current_syscall == __NR_accept ||
			 current->current_syscall == __NR_accept4 ||
			 current->current_syscall == __NR_bind ||
			 current->current_syscall == __NR_listen)) {
		//nothing to do
	}

	TRACE_SYSCALL_HOOK(current, regs);

	STATISTICS_SYSCALL_EXIT(current);

	current->current_syscall = -1;
	current->bumped = -1;
}

	static int __init
ft_syscall_common_management_init(void)
{
	ft_syscall_info_wq =
		create_singlethread_workqueue("ft_syscall_info_wq");
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_SYSCALL_INFO,
			handle_syscall_info_msg);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_TICKBUMP_INFO,
			handle_bump_info_msg);
#ifdef CONFIG_KMVX
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_CTU_INFO,
			handle_ctu_info_msg);
	pcn_kmsg_register_callback(PCN_KMSG_TYPE_FT_CTU_ACK,
			handle_ctu_ack_msg);
#endif

	syscall_hash = create_hashtable(9973);
	tickbump_hash = create_hashtable(1009);
#ifdef CONFIG_KMVX
	ctu_hash = create_hashtable(1013);
	cfu_hash = create_hashtable(1013);
	ctu_ack_table = create_hashtable(1024);
	//cfu_ack_table = create_hashtable(1024);
#endif
	return 0;
}

late_initcall(ft_syscall_common_management_init);
