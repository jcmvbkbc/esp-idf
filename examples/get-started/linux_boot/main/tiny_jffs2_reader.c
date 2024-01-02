#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "tiny_jffs2_reader.h"

#define JFFS2_MAGIC_BITMASK 0x1985

#define JFFS2_NODETYPE_DIRENT 0xe001
#define JFFS2_NODETYPE_INODE 0xe002

struct jffs2_node {
	uint16_t magic;
	uint16_t nodetype;
	uint32_t totlen;
	uint32_t hdr_crc;
};

struct jffs2_dirent {
	uint32_t parent_inode;
	uint32_t version;
	uint32_t inode;
	uint32_t mctime;
	uint8_t name_size;
	uint8_t type;
	uint8_t unused[2];
	uint32_t node_crc;
	uint32_t name_crc;
	uint8_t name[];
};

struct jffs2_inode {
	uint32_t inode;
	uint32_t version;
	uint32_t mode;
	uint16_t uid;
	uint16_t gid;
	uint32_t isize;
	uint32_t atime;
	uint32_t mtime;
	uint32_t ctime;
	uint32_t offset;
	uint32_t csize; /* compressed size */
	uint32_t dsize; /* uncompressed size */
	uint8_t compr;
	uint8_t usercompr;
	uint16_t flags;
	uint32_t data_crc;
	uint32_t node_crc;
	uint8_t data[];
};

static void memcpy_insn(void *dst, const void *src, size_t sz)
{
	memcpy(dst, src, sz & -4);
	if (sz & 3) {
		uint32_t tmp = *(uint32_t *)(src + (sz & -4));
		memcpy(dst + (sz & -4), &tmp, sz & 3);
	}
}

static int memcmp_insn(const void *a, const void *b, size_t sz)
{
	while (sz >= 4) {
		uint32_t va = *(uint32_t *)a;
		uint32_t vb = *(uint32_t *)b;

		if (va != vb)
			return 1;
		a += 4;
		b += 4;
		sz -= 4;
	}
	if (sz) {
		uint32_t va = *(uint32_t *)a;
		uint32_t vb = *(uint32_t *)b;

		return memcmp(&va, &vb, sz & 3);
	} else {
		return 0;
	}
}

static void jffs2_traverse(struct jffs2_image *img, void *ctx,
			   bool (*f)(void *ctx, struct jffs2_node *node, void *data, size_t sz))
{
	uint32_t off = 0;
	uint32_t block_size = 0x10000;

	while (off < img->sz) {
		struct jffs2_node node;

		if (off + sizeof(node) > img->sz)
			return;
		memcpy(&node, img->data + off, sizeof(node));
		off += sizeof(node);
		if (node.magic == JFFS2_MAGIC_BITMASK) {
			uint32_t len = (node.totlen + 3) & -4;

			if (!f(ctx, &node, img->data + off, node.totlen - sizeof(node)))
				break;
			off += len - sizeof(node);
		} else {
			off = (off + block_size - 1) & - block_size;
		}
	}
}

struct jffs2_lookup_ctx {
	uint32_t parent;
	uint32_t inode_num;
	uint32_t version;
	const char *name;
	size_t name_size;
};

static bool jffs2_lookup_cb(void *ctx, struct jffs2_node *node, void *data, size_t sz)
{
	struct jffs2_lookup_ctx *lookup = ctx;

	if (node->nodetype == JFFS2_NODETYPE_DIRENT) {
		struct jffs2_dirent dirent;

		memcpy(&dirent, data, sizeof(dirent));

		if (dirent.parent_inode == lookup->parent &&
		    dirent.version > lookup->version &&
		    dirent.name_size == lookup->name_size &&
		    memcmp_insn(data + sizeof(dirent), lookup->name, lookup->name_size) == 0) {
			lookup->inode_num = dirent.inode;
			lookup->version = dirent.version;
		}
	}
	return true;
}

uint32_t jffs2_lookup(struct jffs2_image *img, uint32_t parent, const char *name)
{
	struct jffs2_lookup_ctx lookup = {
		.parent = parent,
		.name = name,
		.name_size = strlen(name),
	};

	jffs2_traverse(img, &lookup, jffs2_lookup_cb);
	return lookup.inode_num;
}

struct jffs2_read_ctx {
	uint32_t inode_num;
	void *buf;
	size_t sz;
	uint32_t version;
	struct jffs2_inode inode;
	uint32_t version_min;
	uint32_t version_trunc;
	uint32_t version_compr;
};

static bool jffs2_read_pass1_cb(void *ctx, struct jffs2_node *node, void *data, size_t sz)
{
	struct jffs2_read_ctx *read = ctx;

	if (node->nodetype == JFFS2_NODETYPE_INODE) {
		struct jffs2_inode inode;

		memcpy(&inode, data, sizeof(inode));

		if (inode.inode == read->inode_num) {
			if (!read->version_min || inode.version < read->version_min)
				read->version_min = inode.version;
			if (inode.isize == 0 && inode.version > read->version_trunc)
				read->version_trunc = inode.version;
			if (inode.compr && inode.version > read->version_compr)
				read->version_compr = inode.version;
			if (inode.version > read->inode.version)
				read->inode = inode;
		}
	}
	return true;
}

static bool jffs2_read_pass2_cb(void *ctx, struct jffs2_node *node, void *data, size_t sz)
{
	struct jffs2_read_ctx *read = ctx;

	if (node->nodetype == JFFS2_NODETYPE_INODE) {
		struct jffs2_inode inode;

		memcpy(&inode, data, sizeof(inode));

		if (inode.inode == read->inode_num &&
		    ((read->version == 0 && inode.version == read->version_min) ||
		     (read->version && inode.version > read->version))) {
			read->version = inode.version;
			if (inode.offset < read->sz) {
				uint32_t sz = inode.dsize;

				if (sz > read->sz - inode.offset)
					sz = read->sz - inode.offset;
				memcpy_insn(read->buf + inode.offset, data + sizeof(inode), sz);
			}
		}
	}
	return true;
}

size_t jffs2_read(struct jffs2_image *img, uint32_t inode, void *buf, size_t sz)
{
	struct jffs2_read_ctx read = {
		.inode_num = inode,
		.buf = buf,
		.sz = sz,
	};

	jffs2_traverse(img, &read, jffs2_read_pass1_cb);
	/* inode data is not found */
	if (!read.version_min)
		return -1;
	if (read.version_trunc)
		read.version_min = read.version_trunc;
	/* compression is not supported ATM */
	if (read.version_compr > read.version_min)
		return -1;
	if (read.inode.isize < sz)
		read.sz = read.inode.isize;
	/* clear the buffer in case there are holes */
	memset(buf, 0, read.sz);
	jffs2_traverse(img, &read, jffs2_read_pass2_cb);
	if (read.version != read.inode.version)
		jffs2_traverse(img, &read, jffs2_read_pass2_cb);
	return read.sz;
}
