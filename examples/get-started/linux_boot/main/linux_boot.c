/* Linux boot Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "esp_system.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tiny_jffs2_reader.h"
#include "bootparam.h"

static const esp_partition_t *find_partition(const char *name)
{
	esp_partition_iterator_t it;
	const esp_partition_t *part;

	it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, name);
	if (!it)
		return NULL;
	part = esp_partition_get(it);
	return part;
}

static void check_partition_mapping(const char *name, const esp_partition_t *part,
				    const void *ptr)
{
	const uint32_t mask = 0x01ffffff;

	if (((uint32_t)ptr & mask) != (part->address & mask)) {
		ESP_LOGE(__func__, "mapping %s: expected: 0x%08" PRIx32 ", actual: %p\n",
			 name, part->address & mask, ptr);
		abort();
	}
}

static const void *map_partition_part(const esp_partition_t *part, uint32_t size)
{
	const void *ptr;
	esp_partition_mmap_handle_t handle;

	if (esp_partition_mmap(part, 0, size,
			       ESP_PARTITION_MMAP_INST, &ptr, &handle) != ESP_OK)
		abort();
	return ptr;
}

static const void *map_partition_name_part(const char *name, uint32_t size)
{
	const esp_partition_t *part = find_partition(name);

	if (!part)
		return NULL;
	return map_partition_part(part, size);
}

static void align_mapping_address(uint32_t addr)
{
	const esp_partition_t *part = find_partition("factory");
	uint32_t sz = 0x10000;

	for (;;) {
		const void *ptr = map_partition_part(part, sz);
		uint32_t next_map = ((uint32_t)ptr & 0x01ffffff) + sz;

		if (next_map == addr)
			return;
		if (!ptr || next_map > addr)
			abort();
		sz += addr - next_map;
	}
}

#define CMDLINE_MAX 260

#ifdef CONFIG_LINUX_COMMAND_LINE
static void parse_cmdline(const void *ptr, uint32_t size, struct bp_tag tag[])
{
	struct jffs2_image img = {
		.data = (void *)ptr,
		.sz = size,
	};
	uint32_t cmdline_inode = jffs2_lookup(&img, 1, "cmdline");

	if (cmdline_inode) {
		char *cmdline = (char *)tag[1].data;
		size_t rd = jffs2_read(&img, cmdline_inode, cmdline, CMDLINE_MAX - 1);

		if (rd != -1) {
			tag[1].id = BP_TAG_COMMAND_LINE;
			cmdline[rd] = 0;
			ESP_LOGI(__func__, "found /etc/cmdline [%d] = '%s'\n", rd, cmdline);
		}
	}
}
#endif

/* map 8M FLASH linearly, 0 -> 0x40400000 */
static void map_flash_esp32(void)
{
	int i;

	//*(uint32_t *)0x3ff00040 |= 1 << 10;
	//*(uint32_t *)0x3ff00044 &= ~6;
	//*(uint32_t *)0x3ff0005c &= ~6;

	for (i = 0; i < 128; ++i) {
		((volatile uint32_t *)DR_REG_FLASH_MMU_TABLE_PRO)[i + 128] = i;
		((volatile uint32_t *)DR_REG_FLASH_MMU_TABLE_APP)[i + 128] = i;
	}
}

static const void *map_partition_range(uint32_t start, uint32_t end, struct bp_tag tag[])
{
	const void *rv = NULL;
	esp_partition_iterator_t it;

	map_flash_esp32();
	it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);
	while (it) {
		const esp_partition_t *part = esp_partition_get(it);

		ESP_LOGI(__func__, "0x%08"PRIx32"/0x%08"PRIx32" \"%s\"",
			 part->address, part->size, part->label);
		//if (part->address > start)
		//	align_mapping_address(part->address);

		if (part->address >= start &&
		    part->address + part->size <= end) {
			const void *ptr = (void *)0x40400000 + part->address;//map_partition_part(part, part->size);

			//check_partition_mapping(part->label, part, ptr);
			ESP_LOGI(__func__, "0x%08"PRIx32"/0x%08"PRIx32" -> %p \"%s\"",
				 part->address, part->size, ptr, part->label);
			start = part->address + part->size;
			if (!strcmp(part->label, "linux"))
				rv = ptr;
#ifdef CONFIG_LINUX_COMMAND_LINE
			if (!strcmp(part->label, "etc"))
				parse_cmdline(ptr, part->size, tag);
#endif
		}
		it = esp_partition_next(it);
	}
	return rv;
}

static void dump_mmu_area(int start, int n)
{
	int i;

	for (i = 0; i < n; ++i) {
		if (!(i % 16))
			printf("\n0x%04x: ", i + start);
		printf("  0x%08" PRIx32, ((uint32_t *)DR_REG_FLASH_MMU_TABLE_PRO)[i + start]);
	}
	printf("\n");
}

static void dump_mmu(void)
{
	printf("VA 0x3f400000 64K pages");
	dump_mmu_area(0, 64);
	printf("VA 0x40000000 64K pages");
	dump_mmu_area(64, 64);
	printf("VA 0x40400000 64K pages");
	dump_mmu_area(128, 64);
	printf("VA 0x40800000 64K pages");
	dump_mmu_area(192, 64);
	printf("VA 0x3f800000 32K pages");
	dump_mmu_area(1152, 128);
}

static void dump_mem(uint32_t addr, uint32_t sz)
{
	uint32_t i;

	for (i = 0; i < sz; i += 4) {
		if (!(i % 16))
			printf("\n0x%08" PRIx32 " ", addr + i);
		printf(" 0x%08" PRIx32, *(uint32_t *)(addr + i));
	}
}

static void map_psram_to_iram(void)
{
#if 0
	uint32_t *dst = (uint32_t *)DR_REG_MMU_TABLE + 0x100;
	uint32_t *src = (uint32_t *)DR_REG_MMU_TABLE + 0x180;
	int i;

	for (i = 0; i < 0x80; ++i) {
		dst[i] = src[i];
	}
#endif
}

static void cache_partition(const char *name)
{
	esp_partition_iterator_t it;
	const esp_partition_t *part;
	char v;

	it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, name);
	part = esp_partition_get(it);
	if (esp_partition_read(part, 0, &v, 1) != ESP_OK)
		abort();
}

static char IRAM_ATTR space_for_vectors[4096] __attribute__((aligned(4096)));

#define N_TAGS (3 + CMDLINE_MAX / sizeof(struct bp_tag))

static void IRAM_ATTR map_flash_and_go(void)
{
	struct bp_tag tag[N_TAGS] = {
		[0] = {.id = BP_TAG_FIRST},
		[1] = {.id = BP_TAG_LAST, .size = CMDLINE_MAX},
		[N_TAGS - 1] = {.id = BP_TAG_LAST},
	};

	const void *ptr;// = map_partition_name_part("factory", 0x10000);
	uint32_t start = 0x00040000;
	uint32_t end = 0x01000000;

	ptr = map_partition_range(start, end, tag);
	dump_mmu();

	dump_mem(0x40440000, 64);
	dump_mem(0x40840000, 64);
	dump_mem(0x3f800000, 64);

	printf("linux ptr = %p\n", ptr);
	printf("vectors ptr = %p\n", space_for_vectors);
	//dump_mem(0x3ff00000, 0x100);

	map_psram_to_iram();

	cache_partition("nvs");

	//extern int g_abort_on_ipc;
	//g_abort_on_ipc = 1;

	/* stop the other core */
	*(volatile uint32_t *)0x3ff00034 = 0;
	*(volatile uint32_t *)0x3ff0002c = 1;
	*(volatile uint32_t *)0x3ff00030 = 0;
	*(volatile uint32_t *)0x3ff0002c = 0;

	/* manage cache */
	//*(volatile uint32_t *)0x3ff00044 |= 0x18;
	*(volatile uint32_t *)0x3ff00044 |= 1;
	*(volatile uint32_t *)0x3ff00044 &= ~2;

	//*(volatile uint32_t *)0x3ff0005c |= 0x18;
	*(volatile uint32_t *)0x3ff0005c |= 1;
	*(volatile uint32_t *)0x3ff0005c &= ~2;

	*(volatile uint32_t *)0x3ff00040 &= ~0x8;
	*(volatile uint32_t *)0x3ff00040 |= 0x10;
	*(volatile uint32_t *)0x3ff00040 &= ~0x10;
	while (!(*(volatile uint32_t *)0x3ff00040 & 0x20));
	*(volatile uint32_t *)0x3ff00040 |= 0x8;

	*(volatile uint32_t *)0x3ff00058 &= ~0x8;
	*(volatile uint32_t *)0x3ff00058 |= 0x10;
	*(volatile uint32_t *)0x3ff00058 &= ~0x10;
	while (!(*(volatile uint32_t *)0x3ff00058 & 0x20));
	*(volatile uint32_t *)0x3ff00058 |= 0x8;

	/* stop watchdogs */
	//*(volatile uint32_t *)0x3ff480a4 = 0x50d83aa1;
	//*(volatile uint32_t *)0x3ff4808c = 0;

	*(volatile uint32_t *)0x3ff5f064 = 0x50d83aa1;
	*(volatile uint32_t *)0x3ff5f048 = 0;

	*(volatile uint32_t *)0x3ff60064 = 0x50d83aa1;
	*(volatile uint32_t *)0x3ff60048 = 0;

	asm volatile ("mov a2, %1 ; jx %0" :: "r"(ptr), "r"(tag) : "a2");
}

static void linux_task(void *p)
{
	map_flash_and_go();
	esp_restart();
}

void linux_boot(void)
{
	xTaskCreatePinnedToCore(linux_task, "linux_task", 4096, NULL, 5, NULL, 0);
}
