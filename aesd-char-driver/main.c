/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Jaeseo Lee"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    flip->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */


    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_buffer_entry *temp_entry;
    size_t char_offset = 0;
    size_t char_remain = 0;

    if(mutex_lock_interruptible(&aesd_device.aesd_lock) ! = 0)
    {
        return -ERESTART;
    }

    temp_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&(aesd_device.circ_buf), *f_pos,&char_offset);

    if(temp_entry==NULL)
    {
        retval=0;
    }
    else
    {
        char_remain = temp_entry->size - char_offset;

        if(count == char_remain)
        {
            retval = count;
        }
        else
        {
            retval = char_remain;
        }

        if(copy_to_user(buf, temp_entry->buffptr + char_offset,retval) !=0)
        {
            retval = -1;
        }
    }

    *f_pos = *f_pos + retval;

    mutex_unlock(&aesd_device.aesd_lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    if(mutex_lock_interruptible(&(aesd_device.aesd_lock)) !=0)
    {
        return -1;
    }

    if(aesd_device.buff_str == NULL)
    {
        aesd_device.buff_str = kmalloc(count + 1, GFP_KERNEL);
        memset(aesd_device.buff_str,0, count+1);

        if(copy_from_user(&aesd_device.buff_str[0], buf, count) !=0)
        {
            retval = -1;
        }
        else
        {
            retval = count;
        }
    }

    if(aesd_device.buff_str[(count+curr_count) - 1] == '\n')
    {
        const char *ret_entry;
        struct aesd_buffer_entry *new_entry;
        new_entry = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
        new_entry->size=count+curr_count;
        new_entry->buffptr=aesd_device.buff_str;

        ret_entry = aesd_circular_buffer_add_entry(&aesd_device.circ_buff, new_entry);
        kfree(ret_entry);
        aesd_device.buff_str = NULL;
    }

    *f_pos = *f_pos + retval;

    mutex_unlock(&(aesd_device.aesd_lock));

    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}


int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    mutex_init(&aesd_device.aesd_lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }

    return result;
}

void aesd_cleanup_module(void)
{
    struct aesd_buffer_entry *temp_entry;
    size_t;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    kfree(aesd.buff_str);

    AESD_CIRCULAR_BUFFER_FOREACH(temp_entry, &aesd_device.circ_buff,i)
    {
        kfree(temp_entry->buffptr);
    }

    mutex_destory(&aesd_device.aesd_lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
