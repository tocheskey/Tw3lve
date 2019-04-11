//  Comes from Electra, adapted for FAT binary support by me
//
//  amfi_utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "amfi_utils.h"
#include "patchfinder64.h"
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <dlfcn.h>
#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>
#include "stdio.h"
#include <sys/sysctl.h>
#include "kernel_slide.h"
#include "VarHolder.h"
#include "Kernel_Exec.h"
#include "KernelMemory.h"
#include "common.h"
#include "CSCommon.h"

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    if (code_dir == NULL) {
        printf("NULL passed to getSHA256inplace!\n");
        return;
    }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getSHA256(const uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    getSHA256inplace(code_dir, out);
    return out;
}

uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    BOOL foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        printf("[-] %s is 32bit. What are you doing here?\n", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) { //FAT binary magic
        
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                printf("[*] Found arm64\n");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        
        if (!foundarm64) { // by the end of the day there's no arm64 found
            printf("[-] No arm64? RIP\n");
            fclose(fd);
            return NULL;
        }
    }
    else {
        printf("[-] %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        fclose(fd);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

//from xerub
int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

void hex_fill(char *buf, size_t max)
{
    static const char hexdigit[16] = "0123456789abcdef";
    
    unsigned int ms = (unsigned int) time(NULL) * 1000;
    srandom(ms);
    if(max < 1)
        return;
    --max;
    
    for(int i = 0; i < max; ++i)
        buf[i] = hexdigit[random() % 16];
    buf[max] = '\0';
}

OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef  _Nullable *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef  _Nullable *information);
CFStringRef (*_SecCopyErrorMessageString)(OSStatus status, void * __nullable reserved) = NULL;
extern int MISValidateSignatureAndCopyInfo(NSString *file, NSDictionary *options, NSDictionary **info);

extern NSString *MISCopyErrorStringForErrorCode(int err);
extern NSString *kMISValidationOptionRespectUppTrustAndAuthorization;
extern NSString *kMISValidationOptionValidateSignatureOnly;
extern NSString *kMISValidationOptionUniversalFileOffset;
extern NSString *kMISValidationOptionAllowAdHocSigning;
extern NSString *kMISValidationOptionOnlineAuthorization;

enum cdHashType {
    cdHashTypeSHA1 = 1,
    cdHashTypeSHA256 = 2
};

static char *cdHashName[3] = {NULL, "SHA1", "SHA256"};

static enum cdHashType requiredHash = cdHashTypeSHA256;

#define TRUST_CDHASH_LEN (20)

NSString *cdhashFor(NSString *file) {
    NSString *cdhash = nil;
    SecStaticCodeRef staticCode;
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)file, kCFURLPOSIXPathStyle, false), kSecCSDefaultFlags, NULL, &staticCode);
    const char *filename = file.UTF8String;
    if (result != errSecSuccess) {
        if (_SecCopyErrorMessageString != NULL) {
            CFStringRef error = _SecCopyErrorMessageString(result, NULL);
            LOGME("Unable to generate cdhash for %s: %s", filename, [(__bridge id)error UTF8String]);
            CFRelease(error);
        } else {
            LOGME("Unable to generate cdhash for %s: %d", filename, result);
        }
        return nil;
    }
    
    CFDictionaryRef cfinfo;
    result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &cfinfo);
    NSDictionary *info = CFBridgingRelease(cfinfo);
    CFRelease(staticCode);
    if (result != errSecSuccess) {
        LOGME("Unable to copy cdhash info for %s", filename);
        return nil;
    }
    NSArray *cdhashes = info[@"cdhashes"];
    NSArray *algos = info[@"digest-algorithms"];
    NSUInteger algoIndex = [algos indexOfObject:@(requiredHash)];
    
    if (cdhashes == nil) {
        LOGME("%s: no cdhashes", filename);
    } else if (algos == nil) {
        LOGME("%s: no algos", filename);
    } else if (algoIndex == NSNotFound) {
        LOGME("%s: does not have %s hash", cdHashName[requiredHash], filename);
    } else {
        cdhash = [cdhashes objectAtIndex:algoIndex];
        if (cdhash == nil) {
            LOGME("%s: missing %s cdhash entry", file.UTF8String, cdHashName[requiredHash]);
        }
    }
    return cdhash;
}


bool is_amfi_cache(NSString *path) {
    return MISValidateSignatureAndCopyInfo(path, @{kMISValidationOptionAllowAdHocSigning: @YES, kMISValidationOptionRespectUppTrustAndAuthorization: @YES}, NULL) == 0;
}

struct trust_mem {
    uint64_t next; //struct trust_mem *next;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

NSArray *filteredHashes(uint64_t trust_chain, NSDictionary *hashes) {
#if !__has_feature(objc_arc)
    NSArray *result;
    @autoreleasepool {
#endif
        NSMutableDictionary *filtered = [hashes mutableCopy];
        for (NSData *cdhash in [filtered allKeys]) {
            if (is_amfi_cache(filtered[cdhash])) {
                LOGME("%s: already in static trustcache, not reinjecting", [filtered[cdhash] UTF8String]);
                [filtered removeObjectForKey:cdhash];
            }
        }
        
        struct trust_mem search;
        search.next = trust_chain;
        while (search.next != 0) {
            uint64_t searchAddr = search.next;
            kreadOwO(searchAddr, &search, sizeof(struct trust_mem));
            //INJECT_LOG("Checking %d entries at 0x%llx", search.count, searchAddr);
            char *data = malloc(search.count * TRUST_CDHASH_LEN);
            kreadOwO(searchAddr + sizeof(struct trust_mem), data, search.count * TRUST_CDHASH_LEN);
            size_t data_size = search.count * TRUST_CDHASH_LEN;
            
            for (char *dataref = data; dataref <= data + data_size - TRUST_CDHASH_LEN; dataref += TRUST_CDHASH_LEN) {
                NSData *cdhash = [NSData dataWithBytesNoCopy:dataref length:TRUST_CDHASH_LEN freeWhenDone:NO];
                NSString *hashName = filtered[cdhash];
                if (hashName != nil) {
                    LOGME("%s: already in dynamic trustcache, not reinjecting", [hashName UTF8String]);
                    [filtered removeObjectForKey:cdhash];
                    if ([filtered count] == 0) {
                        free(data);
                        return nil;
                    }
                }
            }
            free(data);
        }
        LOGME("Actually injecting %lu keys", [[filtered allKeys] count]);
#if __has_feature(objc_arc)
        return [filtered allKeys];
#else
        result = [[filtered allKeys] retain];
    }
    return [result autorelease];
#endif
}


int injectTrustCache(NSArray <NSString*> *files, uint64_t trust_chain, int (*pmap_load_trust_cache)(uint64_t, size_t))
{
    @autoreleasepool {
        struct trust_mem mem;
        uint64_t kernel_trust = 0;
        
        mem.next = rk64(trust_chain);
        mem.count = 0;
        uuid_generate(mem.uuid);
        
        NSMutableDictionary *hashes = [NSMutableDictionary new];
        int errors=0;
        
        for (NSString *file in files) {
            NSString *cdhash = cdhashFor(file);
            if (cdhash == nil) {
                errors++;
                continue;
            }
            
            if (hashes[cdhash] == nil) {
                LOGME("%s: OK", file.UTF8String);
                hashes[cdhash] = file;
            } else {
                LOGME("%s: same as %s (ignoring)", file.UTF8String, [hashes[cdhash] UTF8String]);
            }
        }
        unsigned numHashes = (unsigned)[hashes count];
        
        if (numHashes < 1) {
            LOGME("Found no hashes to inject");
            return errors;
        }
        
        
        NSArray *filtered = filteredHashes(mem.next, hashes);
        unsigned hashesToInject = (unsigned)[filtered count];
        LOGME("%u new hashes to inject", hashesToInject);
        if (hashesToInject < 1) {
            return errors;
        }
        
        size_t length = (32 + hashesToInject * TRUST_CDHASH_LEN + 0x3FFF) & ~0x3FFF;
        char *buffer = malloc(hashesToInject * TRUST_CDHASH_LEN);
        if (buffer == NULL) {
            LOGME("Unable to allocate memory for cdhashes: %s", strerror(errno));
            return -3;
        }
        char *curbuf = buffer;
        for (NSData *hash in filtered) {
            memcpy(curbuf, [hash bytes], TRUST_CDHASH_LEN);
            curbuf += TRUST_CDHASH_LEN;
        }
        kernel_trust = kmem_alloc(length);
        
        mem.count = hashesToInject;
        kwriteOwO(kernel_trust, &mem, sizeof(mem));
        kwriteOwO(kernel_trust + sizeof(mem), buffer, mem.count * TRUST_CDHASH_LEN);
        if (pmap_load_trust_cache != NULL) {
            if (pmap_load_trust_cache(kernel_trust, length) != ERR_SUCCESS) {
                return -4;
            }
        } else {
            wk64(trust_chain, kernel_trust);
        }
        
        return (int)errors;
    }
}


__attribute__((constructor))
void ctor() {
    void *lib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (lib != NULL) {
        _SecCopyErrorMessageString = dlsym(lib, "SecCopyErrorMessageString");
        dlclose(lib);
    }
}
