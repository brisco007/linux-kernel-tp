/*
 * Virtio caesar implementation.
 *
 *  Copyright 2022 Dufy TEGUIA LIG-IMAG
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */
#include <linux/cdev.h>
#include <linux/virtio.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/io.h>               /* io map */
#include <linux/dma-mapping.h>      /* DMA */
#include <linux/kernel.h>           /* kstrtoint() func */
#include <linux/virtio_config.h>    /* find_single_vq() func */
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/slab.h>
//virtio id of the caesar device
//TODO keep in the template
#define VIRTIO_ID_CAESAR 100
#define MAX_SYSFS_SIZE 20
/* big enough to contain a string representing an integer */
#define MAX_DATA_SIZE 100

//TODO keep in the template
struct virtcaesar_info {
	struct virtqueue *vq;
	struct cdev cdev;
    uint32_t key;
    uint32_t size;
    char direction;
    char message[MAX_DATA_SIZE];
	char output[MAX_DATA_SIZE];
	char req;
	//TODO set k to key setting, s for size setting and o for operation
};

static ssize_t caesar_cipher(void);
static int caesar_dev_open(struct inode *inode, struct file *file);
static int caesar_dev_close(struct inode *inode, struct file *file);
static ssize_t caesar_dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset);
static ssize_t caesar_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);

// initialize file_operations
static const struct file_operations caesar_fops = {
    .owner      = THIS_MODULE,
    .open       = caesar_dev_open,
    .release    = caesar_dev_close,
    .read       = caesar_dev_read,
    .write       = caesar_dev_write
};
static int dev_major = 0;

static struct virtcaesar_info * caesardev_data;
//-----------------------------------------------------------------------------
//                  sysfs - give user access to driver
//-----------------------------------------------------------------------------
//TODO in the template do as un the device driver with "name"
static ssize_t
key_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t count)
{
	struct scatterlist sg_req, sg_out;
	struct scatterlist *request[2];
    /* cast dev into a virtio_device */
    struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtcaesar_info *vi = vdev->priv;
	vi->req ='k';
	if(kstrtou32(buf, 0, &(vi->key))) {
		return -EINVAL;
	}

    /* initialize a single entry sg lists, one for input and one for output */
    sg_init_one(&sg_out, &(vi->key), sizeof(int));
    sg_init_one(&sg_req, &(vi->req), sizeof(int));

    /* build the request */
    request[0] = &sg_req;
    request[1] = &sg_out;

	/* add the request to the queue, in_buf is sent as the buffer idetifier */
    virtqueue_add_sgs(vi->vq, request, 2, 0, NULL, GFP_KERNEL);

    /* notify the device */
	virtqueue_kick(vi->vq);

    return count;
}

static ssize_t
key_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    /* cast dev into a virtio_device */
    struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtcaesar_info *vi = vdev->priv;

    return sprintf(buf, "%d\n", vi->key);
}


static ssize_t
size_store(struct device *dev, struct device_attribute *attr,
        const char *buf, size_t count)
{
    struct scatterlist sg_req, sg_out;
	struct scatterlist *request[2];
    /* cast dev into a virtio_device */
	//TODO tell them that when managing sysfs, they have a device and should use the function
	//dev_to_virtio to get a virtio device and then get the data.
    struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtcaesar_info *vi = vdev->priv;
	vi->req ='s';
	if(kstrtou32(buf, 0, &(vi->size))) {
		return -EINVAL;
	}

    /* initialize a single entry sg lists, one for input and one for output */
    sg_init_one(&sg_out, &(vi->size), sizeof(int));
    sg_init_one(&sg_req, &(vi->req), sizeof(int));

    /* build the request */
    request[0] = &sg_req;
    request[1] = &sg_out;

	/* add the request to the queue, in_buf is sent as the buffer idetifier */
    virtqueue_add_sgs(vi->vq, request, 2, 0, NULL, GFP_KERNEL);

    /* notify the device */
	virtqueue_kick(vi->vq);

    return count;
}

static ssize_t
size_show(struct device *dev, struct device_attribute *attr, char *buf)
{
    /* cast dev into a virtio_device */
    struct virtio_device *vdev = dev_to_virtio(dev);
	struct virtcaesar_info *vi = vdev->priv;

    return sprintf(buf, "%d\n", vi->size);
}

/*
 * struct device_attribute dev_attr_virtio_buf = {
 *     .attr = {
 *         .name = "virtio_buf",
 *         .mode = 0644
 *     },
 *     .show = virtio_buf_show,
 *     .store = virtio_buf_store
 * }
 */
static DEVICE_ATTR_RW(key);
static DEVICE_ATTR_RW(size);


/*
 * The caesar_attr defined above is then grouped in the struct attribute group
 * as follows:
 */
struct attribute *caesar_attrs[] = {
    &dev_attr_key.attr,
    &dev_attr_size.attr,
    NULL,
};

static const struct attribute_group caesar_attr_group = {
    .name = "caesardev", /* directory's name */
    .attrs = caesar_attrs,
};

//FUNCTION THAT GIVES PERMISSIONS TO THE DEVICE
static int caesardev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static const struct attribute_group *attrs_groups[] = {&caesar_attr_group, NULL};


//-----------------------------------------------------------------------------
//                              IRQ functions
//-----------------------------------------------------------------------------

static void caesar_irq_handler(struct virtqueue *vq)
{

	struct virtcaesar_info *vi = vq->vdev->priv;
    unsigned int len;
    int *res = NULL;

    /* get the buffer from virtqueue */
    res = virtqueue_get_buf(vi->vq, &len);
	strncpy(vi->output, (char* )res, MAX_DATA_SIZE);
	printk(KERN_INFO "Here is the operated element %s", vi->output);
}


//-----------------------------------------------------------------------------
//                             driver functions
//-----------------------------------------------------------------------------
static struct class *caesardev_class = NULL;

static int caesar_probe(struct virtio_device *vdev)
{
	int err;
	dev_t dev;
	struct virtcaesar_info *vi = vdev->priv;
	 /* initialize driver data */
	vi = kzalloc(sizeof(struct virtcaesar_info), GFP_KERNEL);
	if (!vi)
	return -ENOMEM;
	
	// allocate chardev region and assign Major number
	err = alloc_chrdev_region(&dev, 0, 1, "caesardev");

	dev_major = MAJOR(dev);
	vi->vq = virtio_find_single_vq(vdev, caesar_irq_handler, "signal");
	if (IS_ERR(vi->vq)) {
        pr_alert("failed to connect to the device virtqueue\n");
	}

       // create sysfs class
    caesardev_class = class_create(THIS_MODULE, "caesardev");
	caesardev_class->dev_uevent = caesardev_uevent;
	
	caesardev_class->dev_groups = attrs_groups;
       // init new device
	cdev_init(&(vi->cdev), &caesar_fops);
	vi->cdev.owner = THIS_MODULE;
	vi->key = 3;
	vi->cdev.ops = &caesar_fops;
	vi->direction = '+';
	vi->size = 36;
	vi->message == NULL;
	vi->output == NULL;
	vdev->priv = vi;
	caesardev_data = vi;
	// add device to the system
	err = cdev_add(&(vi->cdev), MKDEV(dev_major, 0), 1);
	if (err)
		printk(KERN_NOTICE "Error %d adding device caesardev", err);
	
	// create device node /dev/caesar_dev
	device_create(caesardev_class, NULL, MKDEV(dev_major, 0), NULL, "caesardev");
	return 0;
}

static void caesar_remove(struct virtio_device *vdev)
{
	
	struct virtcaesar_info *vi = vdev->priv;
	 device_destroy(caesardev_class, MKDEV(dev_major, 0));
    class_unregister(caesardev_class);
    class_destroy(caesardev_class);
     cdev_del(&(vi->cdev));
    unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
    /* disable interrupts for vqs */
    vdev->config->reset(vdev);

    /* remove virtqueues */
	vdev->config->del_vqs(vdev);

    /* free memory */
	kfree(vi);
}


/*
 * vendor and device (+ subdevice and subvendor)
 * identifies a device we support
 */
static struct virtio_device_id caesar_ids[] = {
    {
        .device = VIRTIO_ID_CAESAR,
        .vendor = VIRTIO_DEV_ANY_ID,
    },
    { 0, },
};

/*
 * id_table describe the device this driver support
 * probe is called when a device we support exist and
 * when we are chosen to drive it.
 * remove is called when the driver is unloaded or
 * when the device disappears
 */
static struct virtio_driver caesar = {
	.driver.name =	"caesar",
	.driver.owner =	THIS_MODULE,
	.id_table =	caesar_ids,
	.probe =	caesar_probe,
	.remove =	caesar_remove,
};



//-----------------------------------------------------------------------------
//                          file functions
//-----------------------------------------------------------------------------

static int caesar_dev_open(struct inode *inode, struct file *file)
{
    printk("CAESARDEV: Device open\n");
    return 0;
}

static int caesar_dev_close(struct inode *inode, struct file *file)
{
    printk("CAESARDEV: Device close\n");
    return 0;
}
static ssize_t caesar_dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    if (caesardev_data->output == NULL) {
    	return -EFAULT;
    }else {
    	if(count > caesardev_data->size ) {
    		return -EINVAL;
       } else {
	  	size_t datalen = strlen(caesardev_data->output);
	  	printk("CAESARDEV: datalen : %d\n", datalen);
	  	printk("CAESARDEV: count : %d\n", count);
		printk("CAESARDEV : message: %s\n", caesardev_data->message);
		if (count > datalen) {
			count = datalen;
		}
		if (copy_to_user(buf, caesardev_data->output, count)) {
			return -EFAULT;
		}
		printk("CAESARDEV: Device read\n");
		return count;
       }
    } 
}

static ssize_t caesar_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{	
	 struct scatterlist sg_req, sg_out, sg_in;
	struct scatterlist *request[3];
	caesardev_data->req ='o';

    size_t datalength = caesardev_data->size, ncopied;
    if (count < datalength) {
        datalength = count;
            ncopied = copy_from_user(caesardev_data->message, buf, datalength);
	    if (ncopied == 0) {
		printk("Copied %zd bytes from the user\n", datalength);
	    } else {
		printk("Could't copy %zd bytes from the user\n", ncopied);
	    }
	} else {
	    caesardev_data->message[datalength] = '\0';
		    /* initialize a single entry sg lists, one for input and one for output */
		sg_init_one(&sg_out, caesardev_data->message, sizeof(int));
		sg_init_one(&sg_req, &(caesardev_data->req), sizeof(int));
		sg_init_one(&sg_in, caesardev_data->output, sizeof(int));

		/* build the request */
		request[0] = &sg_req;
		request[1] = &sg_out;
		request[2] = &sg_in;

		/* add the request to the queue, in_buf is sent as the buffer idetifier */
		virtqueue_add_sgs(caesardev_data->vq, request, 2, 1, caesardev_data->output, GFP_KERNEL);

		/* notify the device */
		virtqueue_kick(caesardev_data->vq);
		printk("CAESARDEV: Device write\n");
	    }
	    return count;

}


/* register driver in kernel pci framework */
module_virtio_driver(caesar);
MODULE_DEVICE_TABLE(virtio, caesar_ids);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("caesar virtio");
MODULE_AUTHOR("Dufy TEGUIA");