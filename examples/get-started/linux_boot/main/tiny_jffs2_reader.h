#ifndef __TINY_JFFS2_READER_H
#define __TINY_JFFS2_READER_H

#include <stddef.h>
#include <stdint.h>

struct jffs2_image {
	void *data;
	size_t sz;
};

uint32_t jffs2_lookup(struct jffs2_image *img, uint32_t parent, const char *name);
size_t jffs2_read(struct jffs2_image *img, uint32_t inode, void *buf, size_t sz);

#endif
