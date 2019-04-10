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
} offsets_t;

extern offsets_t offs;

#endif /* PFOffs_h */
