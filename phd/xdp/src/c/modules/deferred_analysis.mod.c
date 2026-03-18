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

KSYMTAB_FUNC(dw_get_done_mask, "_gpl", "");
KSYMTAB_FUNC(dw_get_verdict, "_gpl", "");
KSYMTAB_FUNC(dw_note_payload_signature, "_gpl", "");
KSYMTAB_FUNC(dw_are_done, "_gpl", "");
KSYMTAB_FUNC(dw_nfqueue_is_stopping, "_gpl", "");
KSYMTAB_FUNC(dw_begin_nfqueue_stop, "_gpl", "");
KSYMTAB_FUNC(dw_meta_get_and_del, "_gpl", "");
KSYMTAB_FUNC(dw_buffer_nfqueue_entry, "_gpl", "");
KSYMTAB_FUNC(dw_quiesce_nfqueue, "_gpl", "");

SYMBOL_CRC(dw_get_done_mask, 0x0ded1547, "_gpl");
SYMBOL_CRC(dw_get_verdict, 0xa880d13b, "_gpl");
SYMBOL_CRC(dw_note_payload_signature, 0x0b6ab8c7, "_gpl");
SYMBOL_CRC(dw_are_done, 0xad3378a8, "_gpl");
SYMBOL_CRC(dw_nfqueue_is_stopping, 0x56fa580a, "_gpl");
SYMBOL_CRC(dw_begin_nfqueue_stop, 0x9bb1a567, "_gpl");
SYMBOL_CRC(dw_meta_get_and_del, 0xb4233bd9, "_gpl");
SYMBOL_CRC(dw_buffer_nfqueue_entry, 0x2d58db32, "_gpl");
SYMBOL_CRC(dw_quiesce_nfqueue, 0x6ad18352, "_gpl");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xfb578fc5, "memset" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0xbf8df930, "register_btf_kfunc_id_set" },
	{ 0x122c3a7e, "_printk" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xc3690fc, "_raw_spin_lock_bh" },
	{ 0xe46021ca, "_raw_spin_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0xe6835428, "nf_reinject" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x609f1c7e, "synchronize_net" },
	{ 0x9166fc03, "__flush_workqueue" },
	{ 0xc3055d20, "usleep_range_state" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0x16bdcecd, "nf_queue_entry_free" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0x91a35752, "kmalloc_caches" },
	{ 0x34004e19, "kmalloc_trace" },
	{ 0xed0bd1a, "nf_queue_entry_get_refs" },
	{ 0xecb0f341, "skb_copy_bits" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xc60d0620, "__num_online_cpus" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xf079b8f9, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "36672C59C93AF08C5C6CCFF");
