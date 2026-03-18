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
	{ 0x122c3a7e, "_printk" },
	{ 0xe6835428, "nf_reinject" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x464f3cf8, "nf_register_queue_handler" },
	{ 0x37cccf24, "init_net" },
	{ 0x83aa9451, "nf_register_net_hook" },
	{ 0xd7ea7094, "nf_unregister_queue_handler" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0x730f66a, "nf_unregister_net_hook" },
	{ 0x609f1c7e, "synchronize_net" },
	{ 0x6ad18352, "dw_quiesce_nfqueue" },
	{ 0xb4233bd9, "dw_meta_get_and_del" },
	{ 0x56fa580a, "dw_nfqueue_is_stopping" },
	{ 0xa880d13b, "dw_get_verdict" },
	{ 0xecb0f341, "skb_copy_bits" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x9bb1a567, "dw_begin_nfqueue_stop" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x2d58db32, "dw_buffer_nfqueue_entry" },
	{ 0xad3378a8, "dw_are_done" },
	{ 0xf079b8f9, "module_layout" },
};

MODULE_INFO(depends, "deferred_analysis");


MODULE_INFO(srcversion, "916DB5E30A991AFEEF1254D");
