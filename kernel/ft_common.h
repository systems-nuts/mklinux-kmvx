/*
 * ft_common.h
 *
 *  Created on: Jul 13, 2016
 *      Author: root
 */

#ifndef KERNEL_FT_COMMON_H_
#define KERNEL_FT_COMMON_H_

#define FT_CSYSC_VERBOSE 0
#if FT_CSYSC_VERBOSE
#define FTPRINTK(...) printk(__VA_ARGS__)
#else
#define FTPRINTK(...) ;
#endif

typedef struct _list_entry{
        struct list_head list;
        char *string; //key
        void *obj; //pointer to the object to store
        spinlock_t slock;
} list_entry_t;

typedef struct _hash_table{
        int size;
        spinlock_t spinlock; //used to lock the whole hash table when adding/removing/looking, not fine grain but effective!
        list_entry_t **table;
}hash_table_t;

/* Create an hash table with size @size.
 *
 */
static hash_table_t* create_hashtable(int size){
        hash_table_t *ret;
        list_entry_t **table;
        int i;

        if(size<1)
                return ERR_PTR(-EFAULT);

        ret= kmalloc(sizeof(*ret), GFP_KERNEL);
        if(!ret)
                return ERR_PTR(-ENOMEM);

        table= kmalloc(sizeof(*table)*size, GFP_KERNEL);
        if(!table){
                kfree(ret);
                return ERR_PTR(-ENOMEM);
        }

        for(i=0;i<size;i++){
                table[i]= NULL;
        }

        ret->size= size;
        ret->table= table;
        spin_lock_init(&ret->spinlock);

        return ret;
}

static unsigned int hash(hash_table_t *hashtable, char *str)
{
    unsigned int hashval;

    /* we start our hash out at 0 */
    hashval = 0;

    /* for each character, we multiply the old hash by 31 and add the current
     * character.  Remember that shifting a number left is equivalent to
     * multiplying it by 2 raised to the number of places shifted.  So we
     * are in effect multiplying hashval by 32 and then subtracting hashval.
     * Why do we do this?  Because shifting and subtraction are much more
     * efficient operations than multiplication.
     */
    for(; *str != '\0'; str++) hashval = *str + (hashval << 5) - hashval;

    /* we then return the hash value mod the hashtable size so that it will
     * fit into the necessary range
     */
    return hashval % hashtable->size;
}

/* Return the object stored in @hashtable in the entry with key @key
 * if any, NULL otherwise.
 */
static void* hash_lookup(hash_table_t *hashtable, char *key){
        unsigned int hashval;
        list_entry_t *head, *entry;
        void* obj= NULL;

        hashval= hash(hashtable, key);
        spin_lock(&hashtable->spinlock);

        head= hashtable->table[hashval];
        if(head){
		list_for_each_entry(entry, &head->list, list){
			if((strcmp(entry->string,key)==0)){
				obj= entry->obj;
				goto out;
			}

		}
        }

out:    spin_unlock(&hashtable->spinlock);
        return obj;
}

/* Add a new object in @hashtable with key @key and object @obj.
 *
 * If an entry with the same key is already present, the object of that entry
 * is returned and the one passed as paramenter is NOT inserted ( => remember to free both @key and @obj)
 *
 * If no entry with the same key are found, NULL is returned and the entry inserted will use both @key and @obj
 * pointers so do not free them while not removed from the hashtable.
 */
static void* hash_add(hash_table_t *hashtable, char *key, void* obj){
        unsigned int hashval;
        void* entry= NULL;
        list_entry_t *new, *head, *app;

        new= kmalloc(sizeof(list_entry_t), GFP_ATOMIC);
        if(!new)
                return ERR_PTR(-ENOMEM);

        INIT_LIST_HEAD(&new->list);
        new->string= key;
        new->obj= obj;

        hashval= hash(hashtable, key);
	if ( !((0 <= hashval) && (hashval < hashtable->size)) ) {
		kfree(new);
		return ERR_PTR(-ENODEV);
	}

        spin_lock(&hashtable->spinlock);

        head= hashtable->table[hashval];

        if(head){
		list_for_each_entry(app, &head->list, list){
			if((strcmp(app->string, key)==0)){
				entry= app->obj;
				spin_unlock(&hashtable->spinlock);
				kfree(new);
				return entry;
			}

		}
        }
        else{
                hashtable->table[hashval]= kmalloc(sizeof(list_entry_t), GFP_ATOMIC);
                if(!hashtable->table[hashval]){
                        spin_unlock(&hashtable->spinlock);
                        kfree(new);
                        return ERR_PTR(-ENOMEM);
                }
                head= hashtable->table[hashval];
                INIT_LIST_HEAD(&head->list);
        }

        list_add(&new->list, &head->list);

        spin_unlock(&hashtable->spinlock);

        return NULL;
}

/* Remove an entry from the hash table @hashtable with key @key.
 *
 * If a corresponding entry to @key is found, the object stored by that entry
 * is returned, NULL otherwise.
 *
 * NOTE: remember to free @key and the object returned eventually.
 */
static void* hash_remove(hash_table_t *hashtable, char *key){
        unsigned int hashval;
        list_entry_t *head, *app;
        list_entry_t *entry= NULL;
        void *obj= NULL;

        hashval= hash(hashtable, key);

        spin_lock(&hashtable->spinlock);
        head= hashtable->table[hashval];
        if(head){
		list_for_each_entry(app, &head->list, list){
			if((strcmp(app->string, key)==0)){
				entry= app;
				list_del(&app->list);
				goto out;
			}

		}
        }
out:
        spin_unlock(&hashtable->spinlock);
        if(entry){
                obj= entry->obj;
                kfree(entry->string);
                kfree(entry);
        }

        return obj;
}

/* syscall_hash is an hash table used to store info about syscalls that need to be synchronized between replicas.
 *
 * The inital idea is that the primary replica performs the syscall and sends meaningfull info for that syscall to the secondary replicas.
 * Those info can be stored in the hash table while the secondary replica reaches the same syscall, or the secondary replica can create an "empty"
 * entry in the hash and sleeps while the primary send the info over.
 *
 * The key of the hash table should be computed with get_key from ft_pid entries and id_syscall of the thread.
 * The object stored is a void* that can be used differently by each syscall.
 */
extern hash_table_t* syscall_hash;

/* Remove an entry from the syscall_hash  with key @key.
 *
 * If a corresponding entry to @key is found, the object stored by that entry
 * is returned, NULL otherwise.
 *
 * NOTE: remember to free @key and the object returned eventually.
 */
void* ft_syscall_hash_remove(char *key){
	return hash_remove(syscall_hash, key);
}

/* Add a new object in sycall_hash with key @key and object @obj.
 *
 * If an entry with the same key is already present, the object of that entry
 * is returned and the one passed as paramenter is NOT inserted ( => remember to free both @key and @obj)
 *
 * If no entry with the same key are found, NULL is returned and the entry inserted will use both @key and @obj
 * pointers so do not free them while not removed from the hashtable.
 */
void* ft_syscall_hash_add(char *key, void* obj){
  return hash_add(syscall_hash, key, obj);
}

/* Return the object stored in syscall_hash in the entry with key @key
 * if any, NULL otherwise.
 */
void* ft_syscall_hash_lookup(char *key){
	return hash_lookup(syscall_hash, key);
}

/* Return a string that is the concatenation of ft_pop_id fields, level, id_array and id_syscall.
 * This uniquely identify each syscall for each ft_pid replica.
 *
 */
char* ft_syscall_get_key(struct ft_pop_rep_id* ft_pop_id, int level, int* id_array, int id_syscall){
        char* string;
        const int size= 1024;
        int pos,i;

        string= kmalloc(size, GFP_ATOMIC);
        if(!string){
		printk("%s impossible to kmalloc\n", __func__);
                return NULL;
	}

        pos= snprintf(string, size,"%d %d %d", ft_pop_id->kernel, ft_pop_id->id, level);
        if(pos>=size)
                goto out_clean;

        if(level){
                for(i=0;i<level;i++){
                        pos= pos+ snprintf(&string[pos], size-pos, " %d", id_array[i]);
                        if(pos>=size)
                                goto out_clean;
                }
        }

        pos= pos+ snprintf(&string[pos], size-pos," %d%c", id_syscall,'\0');
        if(pos>=size)
                goto out_clean;

        return string;

out_clean:
        kfree(string);
        printk("%s: buffer size too small\n", __func__);
        return NULL;

}

void ft_get_key_from_filter(struct net_filter_info *filter, const char* pre_append, char **key, int *key_size){
	char* string;
        const int size= 1024;
        int pos,i;

        string= kmalloc(size, GFP_ATOMIC);
        if(!string){
                printk("%s impossible to kmalloc\n", __func__);
    		*key= NULL;
	        return;
        }

	pos= snprintf(string, size, "%s", pre_append);
	if(pos>=size)
		goto out_clean;

        pos= pos+snprintf(&string[pos], size-pos," %d %d %d", filter->creator.ft_pop_id.kernel, filter->creator.ft_pop_id.id, filter->creator.level);
        if(pos>=size)
                goto out_clean;

        if(filter->creator.level){
                for(i=0;i<filter->creator.level;i++){
                        pos= pos+ snprintf(&string[pos], size-pos, " %d", filter->creator.id_array[i]);
                        if(pos>=size)
                                goto out_clean;
                }
        }

	pos= pos+ snprintf(&string[pos], size-pos," %d", filter->id);
        if(pos>=size)
                goto out_clean;

	if(filter->type & FT_FILTER_CHILD){
		pos= pos+ snprintf(&string[pos], size-pos," %i %i", ntohs(filter->tcp_param.daddr), ntohs(filter->tcp_param.dport));
        	if(pos>=size)
                	goto out_clean;

	}

	pos= pos+ snprintf(&string[pos], size-pos,"%c", '\0');
        if(pos>=size)
                goto out_clean;

	*key= string;
	*key_size= size;
        return ;

out_clean:
        kfree(string);
        printk("%s: buffer size too small\n", __func__);
        *key= NULL;
	return;


}
/* Return a string that is the concatenation of ft_pop_id fields, level, id_array and id_syscall.
 * This uniquely identify each syscall for each ft_pid replica.
 *
 */
char* ft_syscall_get_key_from_ft_pid(struct ft_pid *ft_pid, int id_syscall){
	return ft_syscall_get_key(&ft_pid->ft_pop_id, ft_pid->level, ft_pid->id_array, id_syscall);
}


#endif /* KERNEL_FT_COMMON_H_ */
