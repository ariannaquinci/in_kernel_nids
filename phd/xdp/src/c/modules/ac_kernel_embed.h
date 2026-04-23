#ifndef __DW_AC_KERNEL_EMBED_H__
#define __DW_AC_KERNEL_EMBED_H__

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>

static inline void *dw_ac_malloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

static inline void *dw_ac_realloc(void *ptr, size_t size)
{
	return krealloc(ptr, size, GFP_KERNEL);
}

#define malloc(x) dw_ac_malloc(x)
#define realloc(x, y) dw_ac_realloc((x), (y))
#define free(x) kfree(x)
#define qsort(base, num, size, cmp) sort((base), (num), (size), (cmp), NULL)
#include "../algolib/algo-ac.c"
#undef qsort
#undef free
#undef realloc
#undef malloc

static inline DFA_node *dw_ac_build_patterns(const char *const *patterns, size_t count,int *array,int size_h_s)
{
	state_id = 0;
	return DFA_build((const void **)patterns, count,array,size_h_s);
}

static inline bool dw_ac_match_bytes(DFA_node *root, const u8 *buf, size_t len)
{
	unsigned char *tmp;
	int *match_indices = NULL;
	int matches;

	if (!root || !buf || !len)
		return false;

	tmp = kmalloc(len + 1, GFP_KERNEL);
	if (!tmp)
		return false;

	memcpy(tmp, buf, len);
	tmp[len] = '\0';

	matches = DFA_exec(root, tmp, &match_indices);
	kfree(match_indices);
	kfree(tmp);

	return matches > 0;
}

#endif
