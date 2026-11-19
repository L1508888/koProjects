



static int capture_tls_open(struct inode *inode, struct file *file){

}



static ssize_t ecap_tls_read(struct file *file, char __user *buf, size_t count, loff_t *ppos){
    if (count == 0) {
        return 0;
    }

}




static const struct file_operations ecap_tls_fops =
    {
        .owner = THIS_MODULE,
        .unlocked_ioctl = ecap_tls_ioctl,
        .read = ecap_tls_read,
        .poll = ecap_tls_poll,
};

static struct miscdevice ecap_tls_miscdev ={
        .minor = MISC_DYNAMIC_MINOR,
        .name = "ecap_tls",
        .fops = &ecap_tls_fops,
};