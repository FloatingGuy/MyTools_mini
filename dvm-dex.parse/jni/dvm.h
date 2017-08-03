#ifndef __DVMDEFS_H__
#define __DVMDEFS_H__
#include "utils.h"
#include "dexFile.h"
//#include "elf.h"

typedef struct {
    u4 hashValue;
    void* data;
} HashEntry;

typedef struct {
    int tableSize;
    int numEntries;
    int numDeadEntries;
    HashEntry* pEntries;
} HashTable;

typedef struct {
    char* pathName;
    void* handle;
} SharedLib;

typedef struct {
    struct DexFile* pDexFile;
    const struct DexHeader* pHeader;
} DvmDex;

typedef struct {
    char* cacheFileName;
    DvmDex* pDvmDex;
} RawDexFile;

typedef struct {
    const char*     name;
    unsigned short  nameLen;
} ZipHashEntry;

typedef struct {
    void*   addr;           /* start of data */
    size_t  length;         /* length of data */

    void*   baseAddr;       /* page-aligned base address */
    size_t  baseLength;     /* length of mapping */
} MemMapping;

typedef struct {
    /* open Zip archive */
    int         mFd;

    /* mapped central directory area */
    off_t       mDirectoryOffset;
    MemMapping  mDirectoryMap;

    /* number of entries in the Zip archive */
    int         mNumEntries;

    /*
     * We know how many entries are in the Zip archive, so we can have a
     * fixed-size hash table.  We probe on collisions.
     */
    int         mHashTableSize;
    ZipHashEntry* mHashTable;
} ZipArchive;

typedef struct  {
    ZipArchive  archive;
    //MemMapping  map;
    char*       cacheFileName;
    DvmDex*     pDvmDex;
} JarFile;

typedef struct {
    char* fileName;
    bool isDex;
    bool okayToFree;
    RawDexFile* pRawDexFile;
    JarFile* pJarFile;
    u1* pDexMemory;
} DexOrJar;

//#define SOINFO_NAME_LEN 128
//
//typedef void (*linker_function_t)();
//
//struct link_map_t;
//struct soinfo;
//
//typedef struct {
//    uintptr_t l_addr;
//    char*  l_name;
//    uintptr_t l_ld;
//    struct link_map_t* l_next;
//    struct link_map_t* l_prev;
//} link_map_t;
//
//typedef struct {
//    char name[SOINFO_NAME_LEN];
//    const Elf32_Phdr* phdr;
//    size_t phnum;
//    Elf32_Addr entry;
//    Elf32_Addr base;
//    unsigned size;
//
//    uint32_t unused1;  // DO NOT USE, maintained for compatibility.
//
//    Elf32_Dyn* dynamic;
//
//    uint32_t unused2; // DO NOT USE, maintained for compatibility
//    uint32_t unused3; // DO NOT USE, maintained for compatibility
//
//    struct soinfo* next;
//    unsigned flags;
//
//    const char* strtab;
//    Elf32_Sym* symtab;
//
//    size_t nbucket;
//    size_t nchain;
//    unsigned* bucket;
//    unsigned* chain;
//
//    unsigned* plt_got;
//
//    Elf32_Rel* plt_rel;
//    size_t plt_rel_count;
//
//    Elf32_Rel* rel;
//    size_t rel_count;
//
//    linker_function_t* preinit_array;
//    size_t preinit_array_count;
//
//    linker_function_t* init_array;
//    size_t init_array_count;
//    linker_function_t* fini_array;
//    size_t fini_array_count;
//
//    linker_function_t init_func;
//    linker_function_t fini_func;
//
//// #if defined(ANDROID_ARM_LINKER)
//    // ARM EABI section used for stack unwinding.
//    unsigned* ARM_exidx;
//    size_t ARM_exidx_count;
///* #elif defined(ANDROID_MIPS_LINKER)
//    unsigned mips_symtabno;
//    unsigned mips_local_gotno;
//    unsigned mips_gotsym;
//#endif */
//
//    size_t ref_count;
//    link_map_t link_map;
//
//    bool constructors_called;
//
//    // When you read a virtual address from the ELF file, add this
//    // value to get the corresponding address in the process' address space.
//    Elf32_Addr load_bias;
//} soinfo;

#endif
