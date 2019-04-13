//
//  PFOffs.h
//  tw3lve
//
//  Created by Tanay Findley on 4/9/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#ifndef PFOffs_h
#define PFOffs_h

#include <stdio.h>
#include "common.h"

#define ISADDR(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)
#define SETOFFSET(offset, val) (offs.offset = val)
#define GETOFFSET(offset) offs.offset

typedef struct {
    kptr_t zone_map_ref;
    kptr_t kernel_task;
    kptr_t vnode_put;
    kptr_t vfs_context_current;
    kptr_t vnode_lookup;
    kptr_t add_x0_x0_0x40_ret;
    kptr_t fs_lookup_snapshot_metadata_by_name_and_return_name;
    kptr_t apfs_jhash_getvnode;
    kptr_t vnode_get_snapshot;
    kptr_t trustcache;
    kptr_t pmap_load_trust_cache;
    kptr_t kernel_task_offset_all_image_info_addr;
} offsets_t;

extern offsets_t offs;

extern int (*pmap_load_trust_cache)(uint64_t kernel_trust, size_t length);
int _pmap_load_trust_cache(uint64_t kernel_trust, size_t length);

#endif /* PFOffs_h */
