//
//  utils.m
//  tw3lve
//
//  Created by Tanay Findley on 4/9/19.
//  Copyright © 2019 Tanay Findley. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "utils.h"
#import "kernel_memory.h"
#import "kernel_slide.h"
#include "parameters.h"
#include "KernelUtils.h"
#include "patchfinder64.h"
#include "offsets.h"
#include "common.h"
#include "lzssdec.h"
#include <sys/utsname.h>
#include "PFOffs.h"
#include "remap_tfp_set_hsp.h"
#include "libsnappy.h"
#include "OffsetHolder.h"
#include "vnode_utils.h"
#include <sys/mount.h>
#include "KernelMemory.h"
#include <sys/snapshot.h>
#include <sys/stat.h>
#include "reboot.h"
#include "amfi_utils.h"
#import <copyfile.h>

extern char **environ;
NSData *lastSystemOutput=nil;
int execCmdV(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t)) {
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;
    
    NSMutableString *cmdstr = [NSMutableString stringWithCString:cmd encoding:NSUTF8StringEncoding];
    for (int i=1; i<argc; i++) {
        [cmdstr appendFormat:@" \"%s\"", argv[i]];
    }
    
    valid_pipe = pipe(out_pipe) == ERR_SUCCESS;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == ERR_SUCCESS) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }
    
    if (unrestrict && posix_spawnattr_init(&attrStruct) == ERR_SUCCESS) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);
    LOGME("%s(%d) command: %@", __FUNCTION__, pid, cmdstr);
    
    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }
    
    if (valid_pipe) {
        close(out_pipe[1]);
    }
    
    if (rv == ERR_SUCCESS) {
        if (valid_pipe) {
            NSMutableData *outData = [NSMutableData new];
            char c;
            char s[2] = {0, 0};
            NSMutableString *line = [NSMutableString new];
            while (read(out_pipe[0], &c, 1) == 1) {
                [outData appendBytes:&c length:1];
                if (c == '\n') {
                    LOGME("%s(%d): %@", __FUNCTION__, pid, line);
                    [line setString:@""];
                } else {
                    s[0] = c;
                    [line appendString:@(s)];
                }
            }
            if ([line length] > 0) {
                LOGME("%s(%d): %@", __FUNCTION__, pid, line);
            }
            lastSystemOutput = [outData copy];
        }
        if (waitpid(pid, &rv, 0) == -1) {
            LOGME("ERROR: Waitpid failed");
        } else {
            LOGME("%s(%d) completed with exit status %d", __FUNCTION__, pid, WEXITSTATUS(rv));
        }
        
    } else {
        LOGME("%s(%d): ERROR posix_spawn failed (%d): %s", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int execCmd(const char *cmd, ...) {
    va_list ap, ap2;
    int argc = 1;
    
    va_start(ap, cmd);
    va_copy(ap2, ap);
    
    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);
    
    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;
    
    int rv = execCmdV(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}




void setGID(gid_t gid, uint64_t proc) {
    if (getgid() == gid) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_gid, gid);
    kernel_write32(proc + off_p_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_svgid, gid);
    NSLog(@"Overwritten GID to %i for proc 0x%llx", gid, proc);
}

void setUID (uid_t uid, uint64_t proc) {
    if (getuid() == uid) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_uid, uid);
    kernel_write32(proc + off_p_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_uid, uid);
    kernel_write32(ucred + off_ucred_cr_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_svuid, uid);
    NSLog(@"Overwritten UID to %i for proc 0x%llx", uid, proc);
}

uint64_t selfproc() {
    static uint64_t proc = 0;
    if (!proc) {
        proc = kernel_read64(current_task + OFFSET(task, bsd_info));
        NSLog(@"Found proc 0x%llx for PID %i", proc, getpid());
    }
    return proc;
}

void rootMe (int both, uint64_t proc) {
    setUID(both, proc);
    setGID(both, proc);
}

void unsandbox (uint64_t proc) {
    NSLog(@"Unsandboxed proc 0x%llx", proc);
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    kernel_write64(cr_label + off_sandbox_slot, 0);
}

bool canRead(const char *file) {
    NSString *path = @(file);
    NSFileManager *fileManager = [NSFileManager defaultManager];
    return ([fileManager attributesOfItemAtPath:path error:nil]);
}


static void *load_bytes2(FILE *obj_file, off_t offset, uint32_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

static inline bool clean_file(const char *file) {
    NSString *path = @(file);
    if ([[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil]) {
        return [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }
    return YES;
}

uint32_t find_macho_header(FILE *file) {
    uint32_t off = 0;
    uint32_t *magic = load_bytes2(file, off, sizeof(uint32_t));
    while ((*magic & ~1) != 0xFEEDFACE) {
        off++;
        magic = load_bytes2(file, off, sizeof(uint32_t));
    }
    return off - 1;
}

void initPF64() {
    LOGME("Initializing patchfinder64...");
    const char *original_kernel_cache_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    
    NSString *homeDirectory = NSHomeDirectory();
    
    const char *decompressed_kernel_cache_path = [homeDirectory stringByAppendingPathComponent:@"Documents/kernelcache.dec"].UTF8String;
    if (!canRead(decompressed_kernel_cache_path)) {
        FILE *original_kernel_cache = fopen(original_kernel_cache_path, "rb");
        _assert(original_kernel_cache != NULL, @"Failed to initialize patchfinder64.", true);
        uint32_t macho_header_offset = find_macho_header(original_kernel_cache);
        _assert(macho_header_offset != 0, @"Failed to initialize patchfinder64.", true);
        char *args[5] = { "lzssdec", "-o", (char *)[NSString stringWithFormat:@"0x%x", macho_header_offset].UTF8String, (char *)original_kernel_cache_path, (char *)decompressed_kernel_cache_path};
        _assert(lzssdec(5, args) == ERR_SUCCESS, @"Failed to initialize patchfinder64.", true);
        fclose(original_kernel_cache);
    }
    struct utsname u = { 0 };
    _assert(uname(&u) == ERR_SUCCESS, @"Failed to initialize patchfinder64.", true);
    if (init_kernel(NULL, 0, decompressed_kernel_cache_path) != ERR_SUCCESS || find_strref(u.version, 1, string_base_const, true, false) == 0) {
        _assert(clean_file(decompressed_kernel_cache_path), @"Failed to initialize patchfinder64.", true);
        _assert(false, @"Failed to initialize patchfinder64.", true);
    }
    if (auth_ptrs) {
        LOGME("Detected A12 Device.");
    }
    if (monolithic_kernel) {
        LOGME("Detected monolithic kernel.");
    }
    LOGME("Successfully initialized patchfinder64.");
}



bool is_mountpoint(const char *filename) {
    struct stat buf;
    if (lstat(filename, &buf) != ERR_SUCCESS) {
        return false;
    }
    
    if (!S_ISDIR(buf.st_mode))
        return false;
    
    char *cwd = getcwd(NULL, 0);
    int rv = chdir(filename);
    assert(rv == ERR_SUCCESS);
    struct stat p_buf;
    rv = lstat("..", &p_buf);
    assert(rv == ERR_SUCCESS);
    if (cwd) {
        chdir(cwd);
        free(cwd);
    }
    return buf.st_dev != p_buf.st_dev || buf.st_ino == p_buf.st_ino;
}

bool ensure_directory(const char *directory, int owner, mode_t mode) {
    NSString *path = @(directory);
    NSFileManager *fm = [NSFileManager defaultManager];
    id attributes = [fm attributesOfItemAtPath:path error:nil];
    if (attributes &&
        [attributes[NSFileType] isEqual:NSFileTypeDirectory] &&
        [attributes[NSFileOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFileGroupOwnerAccountID] isEqual:@(owner)] &&
        [attributes[NSFilePosixPermissions] isEqual:@(mode)]
        ) {
        // Directory exists and matches arguments
        return true;
    }
    if (attributes) {
        if ([attributes[NSFileType] isEqual:NSFileTypeDirectory]) {
            // Item exists and is a directory
            return [fm setAttributes:@{
                                       NSFileOwnerAccountID: @(owner),
                                       NSFileGroupOwnerAccountID: @(owner),
                                       NSFilePosixPermissions: @(mode)
                                       } ofItemAtPath:path error:nil];
        } else if (![fm removeItemAtPath:path error:nil]) {
            // Item exists and is not a directory but could not be removed
            return false;
        }
    }
    // Item does not exist at this point
    return [fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:@{
                                                                                       NSFileOwnerAccountID: @(owner),
                                                                                       NSFileGroupOwnerAccountID: @(owner),
                                                                                       NSFilePosixPermissions: @(mode)
                                                                                       } error:nil];
}

uint64_t give_creds_to_process_at_addr(uint64_t proc, uint64_t cred_addr)
{
    uint64_t orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    LOGME("orig_creds = " ADDR, orig_creds);
    if (!ISADDR(orig_creds)) {
        LOGME("failed to get orig_creds!");
        return 0;
    }
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}


void getOffsets() {
    #define GO(x) do { \
    SETOFFSET(x, find_symbol("_" #x)); \
    if (!ISADDR(GETOFFSET(x))) SETOFFSET(x, find_ ##x()); \
    LOGME(#x " = " ADDR " + " ADDR, GETOFFSET(x), kernel_slide); \
    _assert(ISADDR(GETOFFSET(x)), @"Failed to find " #x " offset.", true); \
    SETOFFSET(x, GETOFFSET(x) + kernel_slide); \
    } while (false)
    GO(trustcache);
    if (!auth_ptrs) {
        GO(add_x0_x0_0x40_ret);
    }
    GO(zone_map_ref);
    GO(vfs_context_current);
    GO(vnode_lookup);
    GO(vnode_put);
    GO(kernel_task);
    GO(lck_mtx_lock);
    GO(lck_mtx_unlock);
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        GO(vnode_get_snapshot);
        GO(fs_lookup_snapshot_metadata_by_name_and_return_name);
        GO(apfs_jhash_getvnode);
    }
    if (auth_ptrs) {
        GO(pmap_load_trust_cache);
    }
    
    #undef GO
    found_offs = true;
    term_kernel();
}



void list_all_snapshots(const char **snapshots, const char *origfs, bool has_origfs)
{
    for (const char **snapshot = snapshots; *snapshot; snapshot++) {
        if (strcmp(origfs, *snapshot) == 0) {
            has_origfs = true;
        }
        LOGME("%s", *snapshot);
    }
}

void clear_dev_flags(const char *thedisk)
{
    uint64_t devVnode = vnodeForPath(thedisk);
    _assert(ISADDR(devVnode), @"Failed to clear dev vnode's si_flags.", true);
    uint64_t v_specinfo = kernel_read64(devVnode + koffset(KSTRUCT_OFFSET_VNODE_VU_SPECINFO));
    _assert(ISADDR(v_specinfo), @"Failed to clear dev vnode's si_flags.", true);
    kernel_write32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS), 0);
    uint32_t si_flags = kernel_read32(v_specinfo + koffset(KSTRUCT_OFFSET_SPECINFO_SI_FLAGS));
    _assert(si_flags == 0, @"Failed to clear dev vnode's si_flags.", true);
    _assert(_vnode_put(devVnode) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
}

uint64_t get_kernel_cred_addr()
{
    uint64_t kernel_proc_struct_addr = ReadKernel64(ReadKernel64(GETOFFSET(kernel_task)) + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    return ReadKernel64(kernel_proc_struct_addr + koffset(KSTRUCT_OFFSET_PROC_UCRED));
}


int waitFF(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

void set_platform_binary(uint64_t proc)
{
    uint64_t task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    uint32_t task_t_flags = ReadKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS));
    task_t_flags |= 0x00000400;
    WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags);
}




void renameSnapshot(int rootfd, const char* rootFsMountPoint, const char **snapshots, const char *origfs)
{
    LOGME("Renaming snapshot...");
    rootfd = open(rootFsMountPoint, O_RDONLY);
    _assert(rootfd > 0, @"Error renaming snapshot", true);
    snapshots = snapshot_list(rootfd);
    _assert(snapshots != NULL, @"Error renaming snapshot", true);
    LOGME("Snapshots on newly mounted RootFS:");
    for (const char **snapshot = snapshots; *snapshot; snapshot++) {
        LOGME("\t%s", *snapshot);
    }
    free(snapshots);
    snapshots = NULL;
    NSString *systemVersionPlist = @"/System/Library/CoreServices/SystemVersion.plist";
    NSString *rootSystemVersionPlist = [@(rootFsMountPoint) stringByAppendingPathComponent:systemVersionPlist];
    _assert(rootSystemVersionPlist != nil, @"Error renaming snapshot", true);
    NSDictionary *snapshotSystemVersion = [NSDictionary dictionaryWithContentsOfFile:systemVersionPlist];
    _assert(snapshotSystemVersion != nil, @"Error renaming snapshot", true);
    NSDictionary *rootfsSystemVersion = [NSDictionary dictionaryWithContentsOfFile:rootSystemVersionPlist];
    _assert(rootfsSystemVersion != nil, @"Error renaming snapshot", true);
    if (![rootfsSystemVersion[@"ProductBuildVersion"] isEqualToString:snapshotSystemVersion[@"ProductBuildVersion"]]) {
        LOGME("snapshot VersionPlist: %@", snapshotSystemVersion);
        LOGME("rootfs VersionPlist: %@", rootfsSystemVersion);
        _assert("BuildVersions match"==NULL, @"Error renaming snapshot/root_msg", true);
    }
    const char *test_snapshot = "test-snapshot";
    _assert(fs_snapshot_create(rootfd, test_snapshot, 0) == ERR_SUCCESS, @"Error renaming snapshot", true);
    _assert(fs_snapshot_delete(rootfd, test_snapshot, 0) == ERR_SUCCESS, @"Error renaming snapshot", true);
    char *systemSnapshot = copySystemSnapshot();
    _assert(systemSnapshot != NULL, @"Error renaming snapshot", true);
    uint64_t system_snapshot_vnode = 0;
    uint64_t system_snapshot_vnode_v_data = 0;
    uint32_t system_snapshot_vnode_v_data_flag = 0;
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        system_snapshot_vnode = vnodeForSnapshot(rootfd, systemSnapshot);
        LOGME("system_snapshot_vnode = " ADDR, system_snapshot_vnode);
        _assert(ISADDR(system_snapshot_vnode),  @"Error renaming snapshot", true);
        system_snapshot_vnode_v_data = ReadKernel64(system_snapshot_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_DATA));
        LOGME("system_snapshot_vnode_v_data = " ADDR, system_snapshot_vnode_v_data);
        _assert(ISADDR(system_snapshot_vnode_v_data),  @"Error renaming snapshot", true);
        system_snapshot_vnode_v_data_flag = ReadKernel32(system_snapshot_vnode_v_data + 49);
        LOGME("system_snapshot_vnode_v_data_flag = 0x%x", system_snapshot_vnode_v_data_flag);
        WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag & ~0x40);
    }
    _assert(fs_snapshot_rename(rootfd, systemSnapshot, origfs, 0) == ERR_SUCCESS,  @"Error renaming snapshot", true);
    if (kCFCoreFoundationVersionNumber >= 1535.12) {
        WriteKernel32(system_snapshot_vnode_v_data + 49, system_snapshot_vnode_v_data_flag);
        _assert(_vnode_put(system_snapshot_vnode) == ERR_SUCCESS,  @"Error renaming snapshot", true);
    }
    free(systemSnapshot);
    systemSnapshot = NULL;
    LOGME("Successfully renamed system snapshot.");
    
    
    NOTICE(NSLocalizedString(@"We just took a snapshot of your RootFS in case you want to restore it later. We are going to reboot your device now.", nil), 1, 1);
    
    // Reboot.
    close(rootfd);
    
    LOGME("Rebooting...");
    reboot(RB_QUICK);
}

void preMountFS(const char *thedisk, int root_fs, const char **snapshots, const char *origfs)
{
    LOGME("Pre-Mounting RootFS...");
    _assert(!is_mountpoint("/var/MobileSoftwareUpdate/mnt1"), @"RootFS already mounted, delete OTA file from Settings - Storage if present and reboot.", true);
    const char *rootFsMountPoint = "/private/var/tmp/jb/mnt1";
    if (is_mountpoint(rootFsMountPoint)) {
        _assert(unmount(rootFsMountPoint, MNT_FORCE) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    }
    _assert(clean_file(rootFsMountPoint), @"Failed to clear dev vnode's si_flags.", true);
    _assert(ensure_directory(rootFsMountPoint, 0, 0755), @"Failed to clear dev vnode's si_flags.", true);
    const char *argv[] = {"/sbin/mount_apfs", thedisk, rootFsMountPoint, NULL};
    _assert(execCmdV(argv[0], 3, argv, ^(pid_t pid) {
        uint64_t procStructAddr = get_proc_struct_for_pid(pid);
        LOGME("procStructAddr = " ADDR, procStructAddr);
        _assert(ISADDR(procStructAddr), @"Failed to clear dev vnode's si_flags.", true);
        give_creds_to_process_at_addr(procStructAddr, get_kernel_cred_addr());
    }) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    _assert(execCmd("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    const char *systemSnapshotLaunchdPath = [@(rootFsMountPoint) stringByAppendingPathComponent:@"sbin/launchd"].UTF8String;
    _assert(waitFF(systemSnapshotLaunchdPath) == ERR_SUCCESS, @"Failed to clear dev vnode's si_flags.", true);
    LOGME("Successfully mounted RootFS.");
    
    renameSnapshot(root_fs, rootFsMountPoint, snapshots, origfs);
}



int trust_file(NSString *path) {
    
    NSMutableArray *paths = [NSMutableArray new];
    
    [paths addObject:path];
    
    injectTrustCache(paths, GETOFFSET(trustcache), pmap_load_trust_cache);
    
    return 0;
}




NSString *get_path_file(NSString *resource) {
    NSString *sourcePath = [[NSBundle mainBundle] bundlePath];
    NSString *path = [[sourcePath stringByAppendingPathComponent:resource] stringByStandardizingPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    return path;
}

int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == ERR_SUCCESS); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}


void remountFS() {
    
    //Vars
    int root_fs = open("/", O_RDONLY);
    
    _assert(root_fs > 0, @"Error Opening The Root Filesystem!", true);
    
    const char **snapshots = snapshot_list(root_fs);
    const char *origfs = "orig-fs";
    bool isOriginalFS = false;
    const char *root_disk = "/dev/disk0s1s1";

    if (snapshots == NULL) {
        
        LOGME("No System Snapshot Found! Don't worry, I'll Make One!");
        
        //Clear Dev Flags
        clear_dev_flags(root_disk);
        
        //Pre-Mount
        preMountFS(root_disk, root_fs, snapshots, origfs);
        
        close(root_fs);
    }
    
    list_all_snapshots(snapshots, origfs, isOriginalFS);
    
    uint64_t rootfs_vnode = vnodeForPath("/");
    LOGME("rootfs_vnode = " ADDR, rootfs_vnode);
    _assert(ISADDR(rootfs_vnode), @"Failed to mount", true);
    uint64_t v_mount = ReadKernel64(rootfs_vnode + koffset(KSTRUCT_OFFSET_VNODE_V_MOUNT));
    LOGME("v_mount = " ADDR, v_mount);
    _assert(ISADDR(v_mount), @"Failed to mount", true);
    uint32_t v_flag = ReadKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG));
    if ((v_flag & (MNT_RDONLY | MNT_NOSUID))) {
        v_flag = v_flag & ~(MNT_RDONLY | MNT_NOSUID);
        WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag & ~MNT_ROOTFS);
        _assert(execCmd("/sbin/mount", "-u", root_disk, NULL) == ERR_SUCCESS, @"Failed to mount", true);
        WriteKernel32(v_mount + koffset(KSTRUCT_OFFSET_MOUNT_MNT_FLAG), v_flag);
    }
    _assert(_vnode_put(rootfs_vnode) == ERR_SUCCESS, @"Failed to mount", true);
    _assert(execCmd("/sbin/mount", NULL) == ERR_SUCCESS, @"Failed to mount", true);
    
}

bool mod_plist_file(NSString *filename, void (^function)(id)) {
    LOGME("%s: Will modify plist: %@", __FUNCTION__, filename);
    NSData *data = [NSData dataWithContentsOfFile:filename];
    if (data == nil) {
        LOGME("%s: Failed to read file: %@", __FUNCTION__, filename);
        return false;
    }
    NSPropertyListFormat format = 0;
    NSError *error = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:&format error:&error];
    if (plist == nil) {
        LOGME("%s: Failed to generate plist data: %@", __FUNCTION__, error);
        return false;
    }
    if (function) {
        function(plist);
    }
    NSData *newData = [NSPropertyListSerialization dataWithPropertyList:plist format:format options:0 error:&error];
    if (newData == nil) {
        LOGME("%s: Failed to generate new plist data: %@", __FUNCTION__, error);
        return false;
    }
    if (![data isEqual:newData]) {
        LOGME("%s: Writing to file: %@", __FUNCTION__, filename);
        if (![newData writeToFile:filename atomically:YES]) {
            LOGME("%s: Failed to write to file: %@", __FUNCTION__, filename);
            return false;
        }
    }
    LOGME("%s: Success", __FUNCTION__);
    return true;
}



void restoreRootFS()
{
    LOGME("Restoring RootFS....");
    
    NOTICE(NSLocalizedString(@"Restoring RootFS. Do not lock, or reboot the device!", nil), 1, 1);
    LOGME("Renaming system snapshot back...");
    int rootfd = open("/", O_RDONLY);
    _assert(rootfd > 0, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
    const char **snapshots = snapshot_list(rootfd);
    _assert(snapshots != NULL, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
    const char *snapshot = *snapshots;
    LOGME("%s", snapshot);
    _assert(snapshot != NULL, @"Unable to mount or rename system snapshot.  Delete OTA file from Settings - Storage if present", true);
    
    char *systemSnapshot = copySystemSnapshot();
    _assert(systemSnapshot != NULL, @"Failed to mount", true);
    _assert(fs_snapshot_rename(rootfd, snapshot, systemSnapshot, 0) == ERR_SUCCESS, @"ERROR RENAMING SNAPSHOT!", true);
    
    
    free(systemSnapshot);
    systemSnapshot = NULL;
    close(rootfd);
    free(snapshots);
    snapshots = NULL;
    
    LOGME("Successfully renamed system snapshot back.");
    
    // Clean up.
    
    static const char *cleanUpFileList[] = {
        "/var/cache",
        "/var/lib",
        "/var/stash",
        "/var/db/stash",
        "/var/mobile/Library/Cydia",
        "/var/mobile/Library/Caches/com.saurik.Cydia",
        NULL
    };
    for (const char **file = cleanUpFileList; *file != NULL; file++) {
        clean_file(*file);
    }
    LOGME("Successfully cleaned up.");
    
    // Disallow SpringBoard to show non-default system apps.
    
    LOGME("Disallowing SpringBoard to show non-default system apps...");
    _assert(mod_plist_file(@"/var/mobile/Library/Preferences/com.apple.springboard.plist", ^(id plist) {
        plist[@"SBShowNonDefaultSystemApps"] = @NO;
    }), @"Failed to disallow SpringBoard to show non-default system apps.", true);
    LOGME("Successfully disallowed SpringBoard to show non-default system apps.");
    
    
    // Reboot.
    
    NOTICE(NSLocalizedString(@"RootFS Restored! We will reboot your device.", nil), 1, 1);
    
    LOGME("Rebooting...");
    reboot(RB_QUICK);
    
}


void ux_tfp0(host_t orig_host, uint32_t type)
{
    uint64_t hostport_addr = get_address_of_port(getpid(), orig_host);
    uint32_t old = ReadKernel32(hostport_addr);
    if ((old & type) != type) {
        WriteKernel32(hostport_addr, type);
    }
}

NSString *get_path_res(NSString *resource) {
    static NSString *sourcePath;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sourcePath = [[NSBundle mainBundle] bundlePath];
    });
    
    NSString *path = [[sourcePath stringByAppendingPathComponent:resource] stringByStandardizingPath];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    return path;
}

uint64_t give_creds_to_addr(uint64_t proc, uint64_t cred_addr)
{
    uint64_t orig_creds = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED));
    WriteKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_UCRED), cred_addr);
    return orig_creds;
}


void is_unc0ver_installed()
{
    int f = open("/.installed_unc0ver", O_RDONLY);
    
    if (!(f == -1))
    {
        NOTICE(NSLocalizedString(@"Unc0ver Has Been Detected! Please restore your RootFS (through unc0ver app) and completely remove unc0ver before using Tw3lve. We are going to reboot your device. No changes have been made.", nil), 1, 1);
        reboot(RB_QUICK);
    }
    
}

void extractBootstrap()
{
    int f = open("/.installed_tw3lve", O_RDONLY);
    
    if (f == -1)
    {
        ensure_directory("/tw3", 0, 0755);
        chdir("/tw3");

        NSString *tarFile = get_path_res(@"bootstrap/tar");
        const char *tarFile2 = [tarFile UTF8String];
        
        NSString *bootstrapFile = get_path_res(@"bootstrap/bootstrap.tar");
        
        NSLog(@"%s", tarFile2);
        
        copyfile(tarFile2, "/tw3/tar", 0, COPYFILE_ALL);
        chmod("/tw3/tar", 0777);
        
        trust_file(@"/tw3/tar");
        
        execCmd("/tw3/tar", NULL);
        
         __block pid_t pd = 0;
        //posix_spawn(&pd, "/bin/tar", 0, 0, (char**)&(const char*[]){"/bin/tar", "--preserve-permissions", "--no-overwrite-dir", "-xvf", [bootstrapFile UTF8String], NULL}, NULL);
        
        
    }
}


