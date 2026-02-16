#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

KSYMTAB_FUNC(dw_meta_get_and_del, "_gpl", "");
KSYMTAB_FUNC(dw_is_bypass_skb, "_gpl", "");
KSYMTAB_FUNC(dw_get_done_mask, "_gpl", "");
KSYMTAB_FUNC(dw_are_done, "_gpl", "");
KSYMTAB_FUNC(dw_buffer_marked_skb, "_gpl", "");

SYMBOL_CRC(dw_meta_get_and_del, 0xb4233bd9, "_gpl");
SYMBOL_CRC(dw_is_bypass_skb, 0xdaacd517, "_gpl");
SYMBOL_CRC(dw_get_done_mask, 0x0ded1547, "_gpl");
SYMBOL_CRC(dw_are_done, 0xad3378a8, "_gpl");
SYMBOL_CRC(dw_buffer_marked_skb, 0x93b6026c, "_gpl");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x15ba50a6, "jiffies" },
	{ 0x7f02188f, "__msecs_to_jiffies" },
	{ 0x37a0cba, "kfree" },
	{ 0xe46021ca, "_raw_spin_unlock_bh" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x122c3a7e, "_printk" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x29653d7a, "skb_copy" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0xbf8df930, "register_btf_kfunc_id_set" },
	{ 0x9166fc03, "__flush_workqueue" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x63e816c8, "skb_queue_purge_reason" },
	{ 0x37cccf24, "init_net" },
	{ 0x605df6a0, "dev_get_by_name" },
	{ 0x444de827, "skb_dequeue" },
	{ 0x4c43038b, "netif_receive_skb" },
	{ 0x94218dcd, "kfree_skb_reason" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0x91a35752, "kmalloc_caches" },
	{ 0x34004e19, "kmalloc_trace" },
	{ 0xc60d0620, "__num_online_cpus" },
	{ 0x611464c3, "param_ops_uint" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xc3690fc, "_raw_spin_lock_bh" },
	{ 0xf079b8f9, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "2C0D59020160D46FBE9C7D7");
