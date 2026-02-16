// defer_packet_napi.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/kprobes.h>
#include <linux/smp.h>
#include <linux/cpumask.h>

#define MODULE_NAME "defer_napi"

static struct napi_struct *my_napi;
static struct net_device *dev;
static int n_cpus;

/* Funzione poll: gira in contesto softirq (NET_RX_SOFTIRQ) */
static int my_poll(struct napi_struct *napi, int budget)
{
    int work_done = 0;

    pr_info("%s: NAPI poll on CPU %d (budget=%d)\n",
            MODULE_NAME, smp_processor_id(), budget);

    /* Qui puoi fare il tuo “deferred work” */
    
    work_done = 1;

    napi_complete_done(napi, work_done);
    return work_done;
}

/* kprobe pre_handler: intercetta arrivo pacchetti */
static int probe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    int cur = smp_processor_id();
    int cpu;
    printk("Intercepted napi_gro_receive");
    /* Schedula il nostro NAPI poll su tutte le altre CPU */
    for_each_online_cpu(cpu) {
        if (cpu == cur)
            continue;
        /* Forziamo la CPU target ad attivare il poll */
        smp_call_function_single(cpu, (smp_call_func_t)({
            void __fn(void *info) {
                if (my_napi && napi_schedule_prep(my_napi)) {
                    __napi_schedule(my_napi);
                }
            }
            __fn;
        }), NULL, 0);
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "napi_gro_receive",
    .pre_handler = probe_pre_handler,
};

static int __init mymod_init(void)
{
    int ret;

    n_cpus = num_online_cpus();
    pr_info("%s: init - online cpus = %d\n", MODULE_NAME, n_cpus);

    /* Usa la prima interfaccia disponibile (es. eth0) */
    dev = dev_get_by_name(&init_net, "enp1s0");
    if (!dev) {
    	pr_err("%s: net_device ens3 not found\n", MODULE_NAME);
    	return -ENODEV;
    }

    if (!dev) {
        pr_err("%s: no net_device found\n", MODULE_NAME);
        return -ENODEV;
    }

    /* Allochiamo dinamicamente la nostra napi_struct */
    my_napi = kzalloc(sizeof(*my_napi), GFP_KERNEL);
    if (!my_napi)
        return -ENOMEM;

    netif_napi_add(dev, my_napi, my_poll);
    my_napi->weight = 64;
    napi_enable(my_napi);

    ret = register_kprobe(&kp);
    if (ret) {
        pr_err("%s: register_kprobe failed, err=%d\n", MODULE_NAME, ret);
        napi_disable(my_napi);
        netif_napi_del(my_napi);
        kfree(my_napi);
        return ret;
    }

    pr_info("%s: kprobe registered on %s, napi added to %s\n",
            MODULE_NAME, kp.symbol_name, dev->name);
    return 0;
}

static void __exit mymod_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("%s: kprobe unregistered\n", MODULE_NAME);

    if (my_napi) {
        napi_disable(my_napi);
        netif_napi_del(my_napi);
        kfree(my_napi);
    }

    pr_info("%s: module unloaded\n", MODULE_NAME);
}

module_init(mymod_init);
module_exit(mymod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna ");
MODULE_DESCRIPTION("Deferred work via NAPI on other CPUs");

