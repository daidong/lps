/* Trace do_execv.  Taken basically from Documentation/kprobes.txt */
  #include <linux/kernel.h>
  #include <linux/module.h>
  #include <linux/sched.h>
  #include <linux/kprobes.h>
  #include <linux/kallsyms.h>
  
  /*
   * Pre-entry point for do_execve.
   */
static int my_do_execve(char * filename,
                        char __user *__user *argv,
                        char __user *__user *envp,
                        struct pt_regs * regs)
{
        printk("do_execve for %s from %s\n", filename, current->comm);
        /* Always end with a call to jprobe_return(). */
        jprobe_return();
        /*NOTREACHED*/
        return 0;
}

static struct my_probe = {
    .entry = (kprobe_opcode_t *) my_do_execve
}

init init_module(void)
{
    int ret;
    my_probe.kp.addr = (kprobe_opcode_t *) kallsyms_lookup_name("do_execve");
    if (!my_probe.kp.addr){
        printk("Could not find %s to plant jprobe\n", "do_execv");
        return -1;
    } 
    
    if ((ret = register_jprobe(&my_probe)) < 0){
        printk("register_jprobe failed, return %d\n", ret);
        return -1;
    }
    
    printk("Planted jprobe at %p, handler address %p\n", my_probe.kp.addr, my_probe.entry);
    return 0;
}

void cleanup_module(void)
{
    unregister_jprobe(&my_probe);
    printk("jprobe unregistered\n");
}

MODULE_LICENSE("GPL");