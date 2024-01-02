#ifndef __BOOTPARAM_H
#define __BOOTPARAM_H

#include <stdint.h>

#define BP_TAG_COMMAND_LINE	0x1001
#define BP_TAG_FDT		0x1006
#define BP_TAG_FIRST		0x7B0B
#define BP_TAG_LAST		0x7E0B

struct bp_tag {
	unsigned short id;	/* tag id */
	unsigned short size;	/* size of this record excluding the structure*/
	unsigned long data[];	/* data */
};

struct fdt_header {
	uint32_t magic;
	uint32_t totalsize;
	uint32_t off_dt_struct;
	uint32_t off_dt_strings;
	uint32_t off_mem_rsvmap;
	uint32_t version;
	uint32_t last_comp_version;
	uint32_t boot_cpuid_phys;
	uint32_t size_dt_strings;
	uint32_t size_dt_struct;
};

#endif
