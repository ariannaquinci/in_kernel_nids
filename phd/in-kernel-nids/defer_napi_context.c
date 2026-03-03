// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/kprobes.h>
#include <linux/smp.h>
#include <net/sock.h>

#define MODULE_NAME "defer_napi_context"

static struct kprobe kp = { .symbol_name = "napi_gro_receive" };
static struct napi_struct *target_napi;
static struct net_device *target_dev;

/* Funzione che verrà eseguita sulla CPU target (lazy) */
static void lazy_enqueue_on_cpu(void *info)
{
	struct napi_struct *napi = info;
	int cpu = smp_processor_id();

	if (napi && napi_schedule_prep(napi)) {
		__napi_schedule(napi);
		pr_info("%s: NAPI scheduled (lazy) on CPU %d\n",
			MODULE_NAME, cpu);
	} else {
		pr_info("%s: skipped NAPI (already scheduled or NULL) on CPU %d\n",
			MODULE_NAME, cpu);
	}
}

/* Kprobe handler: intercetta napi_gro_receive */
static int probe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	int cur = smp_processor_id();
	int cpu;

	pr_info("%s: Intercepted napi_gro_receive (cpu=%d) | hardirq=%d softirq=%d\n",
		MODULE_NAME, cur, in_hardirq(), in_softirq());

	for_each_online_cpu(cpu) {
		if (cpu == cur)
			continue;

		/*
		 * smp_call_function_single(cpu, func, info, wait)
		 * - wait = 1 → blocca e manda IPI
		 * - wait = 0 → accoda in call_single_queue → no IPI immediato
		 */
		smp_call_function_single(cpu, lazy_enqueue_on_cpu, target_napi, 0);
	}

	return 0;
}

static int __init defer_init(void)
{
	struct net_device *dev;
	int ret;

	pr_info("%s: init - online CPUs = %u\n",
		MODULE_NAME, num_online_cpus());

	/* trova una net_device con NAPI */
	dev = first_net_device(&init_net);
	for (; dev; dev = next_net_device(dev)) {
		struct napi_struct *napi;
		list_for_each_entry(napi, &dev->napi_list, dev_list) {
			target_napi = napi;
			target_dev = dev;
			pr_info("%s: found NAPI on %s\n",
				MODULE_NAME, dev->name);
			break;
		}
		if (target_napi)
			break;
	}

	if (!target_napi)
		pr_warn("%s: no NAPI found, still loading\n", MODULE_NAME);

	kp.pre_handler = probe_pre_handler;
	ret = register_kprobe(&kp);
	if (ret) {
		pr_err("%s: register_kprobe failed: %d\n", MODULE_NAME, ret);
		return ret;
	}

	pr_info("%s: kprobe active on napi_gro_receive\n", MODULE_NAME);
	return 0;
}

static void __exit defer_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("%s: unloaded, kprobe unregistered\n", MODULE_NAME);
}

module_init(defer_init);
module_exit(defer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arianna Quinci");
MODULE_DESCRIPTION("Deferred NAPI scheduling on other CPUs (lazy, async, no workqueue)");
