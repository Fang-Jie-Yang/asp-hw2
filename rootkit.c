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
dev_t dev_id;

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

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	long ret = 0;

	printk(KERN_INFO "%s\n", __func__);

	switch(ioctl) {

	case IOCTL_MOD_HOOK:
		//do something
		break;
	case IOCTL_MOD_HIDE:
		//do something
		break;
	case IOCTL_MOD_MASQ:
		//do something
		break;
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

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

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
	dev_id = dev;
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
	return 0;

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
	unregister_chrdev_region(major, 1);

	device_destroy(class, dev_id);

	class_destroy(class);

}

module_init(rootkit_init);
module_exit(rootkit_exit);
