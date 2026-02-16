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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x37a0cba, "kfree" },
	{ 0xe46021ca, "_raw_spin_unlock_bh" },
	{ 0x122c3a7e, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xdaacd517, "dw_is_bypass_skb" },
	{ 0x93b6026c, "dw_buffer_marked_skb" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0x91a35752, "kmalloc_caches" },
	{ 0x34004e19, "kmalloc_trace" },
	{ 0x15ba50a6, "jiffies" },
	{ 0xad3378a8, "dw_are_done" },
	{ 0x7f02188f, "__msecs_to_jiffies" },
	{ 0x2d3385d3, "system_wq" },
	{ 0xb2fcb56d, "queue_delayed_work_on" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x83aa9451, "nf_register_net_hook" },
	{ 0xffeedf6a, "delayed_work_timer_fn" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x611464c3, "param_ops_uint" },
	{ 0x9fa7184a, "cancel_delayed_work_sync" },
	{ 0x37cccf24, "init_net" },
	{ 0x730f66a, "nf_unregister_net_hook" },
	{ 0xc3690fc, "_raw_spin_lock_bh" },
	{ 0xf079b8f9, "module_layout" },
};

MODULE_INFO(depends, "deferred_analysis");


MODULE_INFO(srcversion, "60FF34569D570312D3DFFE0");
