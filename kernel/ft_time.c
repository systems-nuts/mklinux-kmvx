/*
 * ft_time.c
 *
 * Author: Marina
 */

#include <linux/ft_replication.h>
#include <linux/popcorn_namespace.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/pcn_kmsg.h>
#include <asm/uaccess.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

#define FT_TIME_VERBOSE 0
#if FT_TIME_VERBOSE
#define FTPRINTK(...) printk(__VA_ARGS__)
#else
#define FTPRINTK(...) ;
#endif

///////////////////////////////////////////////////////////////////////////////
// gettimeofday syscall
///////////////////////////////////////////////////////////////////////////////

struct get_time_info{
	struct timeval tv;
        struct timezone tz;
};

long ft_gettimeofday_primary(struct timeval __user * tv, struct timezone __user * tz){
	long ret= 0;
	struct get_time_info *get_time;

	FTPRINTK("%s called form pid %d\n", __func__, current->pid);
	
	get_time = kmalloc(sizeof(*get_time), GFP_KERNEL);
	memset(get_time, 0, sizeof(*get_time));
	if(!get_time){
        	return -ENOMEM;
        }

	if (likely(tv != NULL)) {
                do_gettimeofday(&get_time->tv);
                if (copy_to_user(tv, &get_time->tv, sizeof(struct timeval))){
                        ret= -EFAULT;
                        goto out;
                }
        }
        if (unlikely(tz != NULL)) {
                memcpy(&get_time->tz, &sys_tz, sizeof(struct timezone));
                if (copy_to_user(tz, &get_time->tz, sizeof(struct timezone))){
                        ret= -EFAULT;
                        goto out;
                }
        }

	if(is_there_any_secondary_replica(current->ft_popcorn)){
		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) get_time, sizeof(*get_time));
	}
out: 
	if(get_time)
		kfree(get_time);

	return ret;

}

static long ft_gettimeofday_primary_after_secondary(struct timeval __user * tv, struct timezone __user * tz){
        long ret= 0;
	struct get_time_info *primary_info= NULL;

        FTPRINTK("%s called from pid %d\n", __func__, current->pid);

        primary_info= (struct get_time_info *)ft_get_pending_syscall_info(&current->ft_pid, current->id_syscall);

        if(!primary_info){
                disable_det_sched(current);
		return ft_gettimeofday_primary(tv, tz);
        }

	if (likely(tv != NULL)) {
                if (copy_to_user(tv, (void*) &primary_info->tv, sizeof(struct timeval))){
                        ret= -EFAULT;
                        goto out;
                }
        }

        if (unlikely(tz != NULL)) {
                if (copy_to_user(tz, (void*) &primary_info->tz, sizeof(struct timezone))){
                        ret= -EFAULT;
                        goto out;
                }
        }

out:
        kfree(primary_info);

        return 0;

}

long ft_gettimeofday_secondary(struct timeval __user * tv, struct timezone __user * tz){
	long ret=0;
	struct get_time_info *primary_info= NULL;
	
	FTPRINTK("%s called from pid %d\n", __func__, current->pid);

	primary_info= (struct get_time_info *)ft_wait_for_syscall_info( &current->ft_pid, current->id_syscall);

	if(!primary_info){
		disable_det_sched(current);
		return ft_gettimeofday_primary(tv, tz);
	}

	if (likely(tv != NULL)) {
                if (copy_to_user(tv, (void*) &primary_info->tv, sizeof(struct timeval))){
                        ret= -EFAULT;
                        goto out;
                }
        }

        if (unlikely(tz != NULL)) {
                if (copy_to_user(tz, (void*) &primary_info->tz, sizeof(struct timezone))){
                        ret= -EFAULT;
                        goto out;
                }
        }

out:
	kfree(primary_info);
	
	return 0;
}

long ft_gettimeofday(struct timeval __user * tv, struct timezone __user * tz)
{
	if (ft_is_primary_replica(current)) {
		return ft_gettimeofday_primary(tv, tz);	
	}
	else if (ft_is_secondary_replica(current)) {
		return ft_gettimeofday_secondary(tv, tz);
	}
	else if (ft_is_primary_after_secondary_replica(current)) {
		return ft_gettimeofday_primary_after_secondary(tv, tz);
	}
	else {
		return -EFAULT;
	}
}

///////////////////////////////////////////////////////////////////////////////
// time syscall
///////////////////////////////////////////////////////////////////////////////

struct time_info {
	time_t tloc;
	long   ret;
};

long ft_time_primary(time_t __user *tloc)
{
	struct time_info *timeinfo;
	time_t i = get_seconds();

        if (tloc) {
                if (put_user(i,tloc))
                        return -EFAULT;
        }
        force_successful_syscall_return();

	if(is_there_any_secondary_replica(current->ft_popcorn)){
		timeinfo = kmalloc(sizeof(struct time_info), GFP_KERNEL);
        	memcpy(&timeinfo->tloc, &i, sizeof(i));
        	timeinfo->ret = i;
		ft_send_syscall_info(current->ft_popcorn, &current->ft_pid, current->id_syscall, (char*) timeinfo, sizeof(struct time_info));
		kfree(timeinfo);
		FTPRINTK("sending time for syscall %d - %d - %d\n", current->id_syscall, current->pid, 0);
	}

	return i;

}

long ft_time_primary_after_secondary(time_t __user *tloc)
{
        struct time_info *timeinfo;
        long ret= 0;

        timeinfo = (struct time_info *) ft_get_pending_syscall_info(&current->ft_pid, current->id_syscall);
        if(timeinfo){
                ret = timeinfo->ret;
                put_user(timeinfo->tloc, tloc);
                kfree(timeinfo);
		return ret;
        }
        else{
        	disable_det_sched(current);
		return ft_time_primary(tloc);
	}

}

long ft_time_secondary(time_t __user *tloc)
{
	struct time_info *timeinfo;
	long ret;

	FTPRINTK("waiting for time %d - %d\n", current->id_syscall, current->pid);
	timeinfo = (struct time_info *) ft_wait_for_syscall_info(&current->ft_pid, current->id_syscall);
	if(!timeinfo){
		return ft_time_primary_after_secondary(tloc);
	}

	ret = timeinfo->ret;
	put_user(timeinfo->tloc, tloc);
	kfree(timeinfo);
	FTPRINTK("got time for syscall %d - %d - %d\n", current->id_syscall, ret, current->pid);

	return ret;
}

long ft_time(time_t __user *tloc)
{
	/* there were no fault the primary is the leader */
	if (ft_is_primary_replica(current)) {
		return ft_time_primary(tloc);
	}
	/* there were no fault the secondary is the follower */
	else if (ft_is_secondary_replica(current)) {
		return ft_time_secondary(tloc);
	}
	/* there were a fault a secondary is now a leader */
	else if (ft_is_primary_after_secondary_replica(current)) {
		return ft_time_primary_after_secondary(tloc);
	}
	else {
		return -EFAULT;
	}
}

