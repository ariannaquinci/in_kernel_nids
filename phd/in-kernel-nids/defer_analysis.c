#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/smp.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("Module to schedule dummy deferred work on other CPUs at packets' arrival");

static struct nf_hook_ops nfho;

static void deferred_work_on_cpu(void *info)
{
    int cpu = smp_processor_id();
    printk(KERN_INFO "Dummy deferred work on CPU %d\n", cpu);
}

static void schedule_work_on_other_cpus(void)
{
    int cpu, this_cpu = smp_processor_id();

    for_each_online_cpu(cpu) {
        if (cpu == this_cpu)
            continue;

        smp_call_function_single(cpu, deferred_work_on_cpu, NULL, 1);
    }
}

static unsigned int nf_hook_func(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    printk(KERN_INFO "Packet intercepted on CPU %d\n", smp_processor_id());
    schedule_work_on_other_cpus();
    return NF_ACCEPT;
}

static int __init my_module_init(void)
{
    nfho.hook = nf_hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Init module\n");
    return 0;
}

static void __exit my_module_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
