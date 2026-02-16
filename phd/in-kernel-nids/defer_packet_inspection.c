// defer_packet_probe.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/errno.h>

#define MODULE_NAME "defer_packet_inspection"

static struct work_struct *my_work;
static int n_cpus;

static void my_work_func(struct work_struct *work)
{
   //dummy deferred work 
   printk("%s: deferred work running on CPU %d\n", MODULE_NAME, smp_processor_id());
}

/* kprobe pre-handler: viene eseguito *prima* della funzione probeata */
static int probe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int cur = smp_processor_id();
    int cpu;
    printk("pre handler kprobe");
    /* schedula sui restantes online CPU */
    for_each_online_cpu(cpu) {
        if (cpu == cur)
            continue;
        /* queue_work_on è sleep-safe e può essere chiamata dal contesto di kprobe */
        queue_work_on(cpu, system_wq, &my_work[cpu]);
    }

    return 0; /* 0 -> continua esecuzione della funzione originale */
}

static struct kprobe kp = {
    .symbol_name = "netif_receive_skb_core", 
    .pre_handler = probe_pre_handler,
};

static int __init mymod_init(void)
{
    int cpu, ret;

    n_cpus = num_online_cpus();
    printk("%s: init - online cpus = %d\n", MODULE_NAME, n_cpus);

    /* allocate array of work_struct, one for each CPU */
    my_work = kcalloc(n_cpus, sizeof(struct work_struct), GFP_KERNEL);
    if (!my_work)
        return -ENOMEM;

    for (cpu = 0; cpu < n_cpus; cpu++)
        INIT_WORK(&my_work[cpu], my_work_func);

    /* registra kprobe */
    ret = register_kprobe(&kp);
    if (ret) {
        pr_err("%s: register_kprobe failed, err=%d\n", MODULE_NAME, ret);
        kfree(my_work);
        return ret;
    }

    printk("%s: kprobe registered on %s\n", MODULE_NAME, kp.symbol_name);
    return 0;
}

static void __exit mymod_exit(void)
{
    int cpu;

    unregister_kprobe(&kp);
    printk("%s: kprobe unregistered\n", MODULE_NAME);

    /* cancella/sincronizza solo i work che potrebbero essere stati schedulati */
    for (cpu = 0; cpu < n_cpus; cpu++)
        cancel_work_sync(&my_work[cpu]);

    kfree(my_work);
    printk("%s: module unloaded\n", MODULE_NAME);
}

module_init(mymod_init);
module_exit(mymod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna");
MODULE_DESCRIPTION("Kprobe that schedules deferred work on other CPUs when a packet arrives");

