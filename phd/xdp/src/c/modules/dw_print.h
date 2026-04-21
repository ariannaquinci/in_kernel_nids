#ifndef __DW_PRINT_H__
#define __DW_PRINT_H__

#include <linux/printk.h>

/*
 * Higher PRINT_LEVEL values suppress more logs.
 * Set PRINT_LEVEL to DW_PRINT_SILENT to disable all logs.
 */
#define DW_PRINT_VERBOSE 0
#define DW_PRINT_INFO    1
#define DW_PRINT_WARN    2
#define DW_PRINT_ERROR   3
#define DW_PRINT_SILENT  4

#ifndef PRINT_LEVEL
#define PRINT_LEVEL DW_PRINT_INFO
#endif

#define DW_PRINT(level, fmt, ...)                                             \
	do {                                                                  \
		if ((level) >= PRINT_LEVEL && PRINT_LEVEL < DW_PRINT_SILENT)  \
			printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__);         \
	} while (0)

#undef pr_debug
#define pr_debug(fmt, ...) DW_PRINT(DW_PRINT_VERBOSE, fmt, ##__VA_ARGS__)

#undef pr_info
#define pr_info(fmt, ...) DW_PRINT(DW_PRINT_INFO, fmt, ##__VA_ARGS__)

#undef pr_notice
#define pr_notice(fmt, ...) DW_PRINT(DW_PRINT_INFO, fmt, ##__VA_ARGS__)

#undef pr_warn
#define pr_warn(fmt, ...) DW_PRINT(DW_PRINT_WARN, fmt, ##__VA_ARGS__)

#undef pr_err
#define pr_err(fmt, ...) DW_PRINT(DW_PRINT_ERROR, fmt, ##__VA_ARGS__)

#endif
