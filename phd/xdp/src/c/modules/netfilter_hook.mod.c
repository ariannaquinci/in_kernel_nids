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
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x730f66a, "nf_unregister_net_hook" },
	{ 0xdaacd517, "dw_is_bypass_skb" },
	{ 0xb4233bd9, "dw_meta_get_and_del" },
	{ 0x93b6026c, "dw_buffer_marked_skb" },
	{ 0xecb0f341, "skb_copy_bits" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0x156682e3, "param_ops_bool" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x37cccf24, "init_net" },
	{ 0x83aa9451, "nf_register_net_hook" },
	{ 0xf079b8f9, "module_layout" },
};

MODULE_INFO(depends, "deferred_analysis");


MODULE_INFO(srcversion, "C19B5E252DCC0AF6A79D716");
