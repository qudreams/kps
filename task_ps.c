#include <linux/module.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/vermagic.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23)
    #define PID(ts) task_tgid_vnr(ts)
#else
    #define PID(ts) ((ts)->tgid)
#endif

pid_t kps_get_sid(struct task_struct* tsk)
{
    pid_t sid = 0;
    rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    sid = task_session_vnr(tsk);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    sid = process_session(tsk);
#else
    sid = tsk->signal->session;
#endif
    rcu_read_unlock();

    return sid;
}

static int kps_get_cmdline(struct task_struct *task, char *buffer, int buflen);

static void do_iterator_process(void)
{
    int res = 0;
    pid_t pid = -1;
    pid_t pgrp = -1;
    pid_t psess = -1;

    struct task_struct* p = NULL;
    char* cmdline = kcalloc(1,PAGE_SIZE,GFP_KERNEL);
    if(cmdline == NULL) { return; }

    rcu_read_lock();
    for_each_process(p) {
        //don't care kernel-thread
        #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
    		if (unlikely(p->flags & PF_KTHREAD))
    			continue;
		#else
    		if (unlikely(!p->mm))
    			continue;
        #endif
        //just care group-leader thread
		if (unlikely(p != p->group_leader))
			continue;

        pid = PID(p);
        if(pid <= 1)
            continue;

        #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
            pgrp = task_pgrp_vnr(p);
        #else
            pgrp = process_group(p);
        #endif
        psess = kps_get_sid(p);

        memset(cmdline,0,PAGE_SIZE);
        res = kps_get_cmdline(p,cmdline,PAGE_SIZE - 1);
        if(res <= 0) { continue; }
        cmdline[res] = '\0';


        printk("pid: %d,pgrp: %d,session: %d,cmdline: %s\n",
            pid,pgrp,psess,cmdline);
    }
    rcu_read_unlock();
}

#ifdef CONFIG_MMU
int kps_get_user_pages(struct task_struct* tsk,
                        struct mm_struct* mm,
                        unsigned long pos,
                        struct page** ppage,
                        struct vm_area_struct** pvma)
{
    int ret = 0;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
       unsigned int gnu_flags = FOLL_FORCE;
       ret = get_user_pages_remote(tsk, mm, pos,
                   1,gnu_flags,ppage,pvma);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
        ret = get_user_pages_remote(tsk, mm, pos,
                1, 0, 1,ppage, pvma);
    #else
        ret = get_user_pages(tsk,mm, pos,
                1, 0, 1,ppage, pvma);
    #endif

    return ret;
}
#endif

#if defined(CONFIG_MMU) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
        static int do_ioremap_port(struct mm_struct *mm,unsigned long addr,
                void* buf,int len,int write,struct vm_area_struct** pvma)
        {
            int ret = -1;
            struct vm_area_struct* vma = NULL;

            #ifdef CONFIG_HAVE_IOREMAP_PROT
                /*
                * Check if this is a VM_IO | VM_PFNMAP VMA, which
                * we can access using slightly different code.
                */
                vma = find_vma(mm, addr);
                if (!vma) { return ret; }

                *pvma = vma;
                if (vma->vm_ops && vma->vm_ops->access)
                    ret = vma->vm_ops->access(vma, addr, buf,
                                  len, write);
            #endif
            return ret;
        }
    #else
        static int do_ioremap_port(struct mm_struct *mm,unsigned long addr,
            void* buf,int len,int write,struct vm_area_struct** pvma)
        {
            return -1;
        }
    #endif
    /*
    * Access another process' address space.
    * Source/target buffer must be kernel space,
    * Do not walk the page table directly, use get_user_pages
    */
    static int kps_access_process_vm(struct task_struct *tsk,
                unsigned long addr, void *buf, int len, int write)
    {
        struct mm_struct *mm;
        struct vm_area_struct *vma;
        void *old_buf = buf;

        mm = get_task_mm(tsk);
        if (!mm)
            return 0;

        down_read(&mm->mmap_sem);
        /* ignore errors, just check how much was successfully transferred */
        while (len) {
            int bytes, ret, offset;
            void *maddr;
            struct page *page = NULL;

            ret = kps_get_user_pages(tsk, mm, addr,&page, &vma);
            if (ret <= 0) {
                ret = do_ioremap_port(mm,addr,buf,len,write,&vma);
                if(ret <= 0)
                    break;
                bytes = ret;
            } else {
                bytes = len;
                offset = addr & (PAGE_SIZE-1);
                if (bytes > PAGE_SIZE-offset)
                    bytes = PAGE_SIZE-offset;

                maddr = kmap(page);
                if (write) {
                    copy_to_user_page(vma, page, addr,
                              maddr + offset, buf, bytes);
                    set_page_dirty_lock(page);
                } else {
                    copy_from_user_page(vma, page, addr,
                                buf, maddr + offset, bytes);
                }
                kunmap(page);
                put_page(page);
            }
            len -= bytes;
            buf += bytes;
            addr += bytes;
        }
        up_read(&mm->mmap_sem);
        mmput(mm);

        return buf - old_buf;
    }
#else
    /*
    * Access another process' address space.
    * - source/target buffer must be kernel space
    */
    static int kps_access_process_vm(struct task_struct *tsk,
            unsigned long addr, void *buf, int len, int write)
    {
        struct vm_area_struct *vma;
        struct mm_struct *mm;

        if (addr + len < addr)
            return 0;

        mm = get_task_mm(tsk);
        if (!mm)
            return 0;

        down_read(&mm->mmap_sem);

        /* the access must start within one of the target process's mappings */
        vma = find_vma(mm, addr);
        if (vma) {
            /* don't overrun this mapping */
            if (addr + len >= vma->vm_end)
                len = vma->vm_end - addr;

            /* only read or write mappings where it is permitted */
            if (write && vma->vm_flags & VM_MAYWRITE)
                len -= copy_to_user((void *) addr, buf, len);
            else if (!write && vma->vm_flags & VM_MAYREAD)
                len -= copy_from_user(buf, (void *) addr, len);
            else
                len = 0;
        } else {
            len = 0;
        }

        up_read(&mm->mmap_sem);
        mmput(mm);
        return len;
    }
#endif

/**
 * kps_get_cmdline() - copy the cmdline value to a buffer.
 * @task:     the task whose cmdline value to copy.
 * @buffer:   the buffer to copy to.
 * @buflen:   the length of the buffer. Larger cmdline values are truncated
 *            to this length.
 * Returns the size of the cmdline field copied. Note that the copy does
 * not guarantee an ending NULL byte.
 */
int kps_get_cmdline(struct task_struct *task, char *buffer, int buflen)
{
	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);

	if (!mm)
		goto out;
	if (!mm->arg_end) {
		goto out_mm;	/* Shh! No looking before we're done */
    }

	len = mm->arg_end - mm->arg_start;
	if (len > buflen)
		len = buflen;

	res = kps_access_process_vm(task, mm->arg_start, buffer, len, 0);

	/*
	 * If the nul at the end of args has been overwritten, then
	 * assume application is using setproctitle(3).
	 */
	if (res > 0 && buffer[res-1] != '\0' && len < buflen) {
		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else {
			len = mm->env_end - mm->env_start;
			if (len > buflen - res)
				len = buflen - res;
			res += kps_access_process_vm(task,mm->env_start,
						 buffer + res, len, 0);
			res = strnlen(buffer, res);
		}
	}

out_mm:
	mmput(mm);
out:
	return res;
}


#define DEVICE_NAME     "kps"

static int __init kps_init(void)
{
    int rc = 0;
    printk("-----Start kernel-task-ps:,"
        "kernel-version: %s\n",UTS_RELEASE);

    do_iterator_process();

    return rc;
}

static void __exit kps_exit(void)
{
    printk("-----Exit kernel-task-ps-----\n");
}

module_init(kps_init);
module_exit(kps_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qudreams");
MODULE_DESCRIPTION(DEVICE_NAME);
MODULE_VERSION(DEVICE_VERSION);
