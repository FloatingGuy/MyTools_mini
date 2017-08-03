#define LOG_TAG "introspy"
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <sys/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <android_runtime/AndroidRuntime.h>
#include "dvm.h"
#include "dexFileParser.h"

//////////////////////

#define HASH_TOMBSTONE ((void*) 0xcbcacccd)

typedef void (*callback_t)(void *entry, char *pkg, int i);

#define IS_DEX(v) ((v)->isDex ? 1:0)
#define DEX_MAGIC2 "dex\n035\0"
#define ODEX_MAGIC "dey\n036\0"
#define SELF_MAGIC "baronpan"

#define true 1
#define false 0
bool loop = true;
bool isSecapk = false;

//void lib_iter(void *data, char *pkg){
//    soinfo *so;
//    SharedLib *entry = (SharedLib *)data;
//    XLOGI("loaded lib: %s", entry->pathName);
//    so = entry->handle;
//
//    if (strstr(entry->pathName, "/system/lib")) {
//        return;
//    }
//
//    dump_file(so->base, so->size, pkg, entry->pathName);
//}

static void* parse_odex(DvmDex *pDvmDex, char* filePath){
    struct DexFile *pDexFile;
    bool has_odex = true;
    u4 optaddr, dexaddr;
    int optsize;
    int size;
    if (!pDvmDex || !pDvmDex->pDexFile) {
       XLOGE("DexFile has invalid structure.");
        return 0;
    }

    pDexFile = pDvmDex->pDexFile;
    if (!pDexFile->pHeader) {
       XLOGE("dex has no header.");
        return 0;
    }

    if (pDexFile->pOptHeader == 0) {
        has_odex = false;
    }

    if ( !has_odex && pDexFile->pHeader->fileSize != 0 ) {
        size = pDexFile->pHeader->dataOff+pDexFile->pHeader->dataSize;
    } else if (has_odex && (pDexFile->pOptHeader->dexLength != 0)) {
        size = pDexFile->pOptHeader->dexLength;
    } else {
		size = 0;
		XLOGE("dex header obfuscation.");
		return 0;
    }

    // confirm magic
	if ((u4)(pDexFile->pHeader->endianTag) != 0x12345678) {
	   XLOGE("dex/odex memory format error.");
	   return 0;
	}
    nativeParserDex((void*)(pDexFile->pHeader),size,isSecapk,filePath);
}

static void dex_iter(void *data, char *pkg, int i){
    DexOrJar *entry = (DexOrJar *)data;
    void *addr;
    DvmDex *pDvmDex;
    JarFile *jarfile;

    XLOGD("loaded dex: %s", entry->fileName);
	if(IS_DEX(entry)){
		pDvmDex = (entry->pRawDexFile)->pDvmDex;
	}else{
		jarfile = entry->pJarFile;
		pDvmDex = jarfile->pDvmDex;
	}
	if(strstr(entry->fileName,"introspy") != NULL)
		return;
	char filePath[1024] = {'\0'};
	char* filename = strrchr(entry->fileName, '/');
    if (!filename) {
        filename = entry->fileName;
    } else {
        filename++;
    }
	snprintf(filePath,1024,"%s/%d%s",pkg,i,filename);
	parse_odex(pDvmDex,filePath);
}

static void hashtable_iter(HashTable *table, callback_t func, char *pkg){
	if(loop == false)
		return;
    loop = false; //lock
    int i;
    HashEntry *entry;
    XLOGD("-- HashTable --");
    XLOGD("table size = %d", table->tableSize);
    XLOGD("num entries = %d", table->numEntries);
    XLOGD("num dead entries = %d", table->numDeadEntries);
    for (i = 0; i < table->tableSize; i++){
        entry = &(table->pEntries[i]);
        if (entry->data != 0 && entry->data != HASH_TOMBSTONE) {
            func(entry->data, pkg, i);
        }
    }
}


#define READWORD(addr) (*((u1 *)(addr)) | *((u1 *)(addr) + 1) << 8)
#define LDRW_OP_MASK 0xF8D0
#define LDRW_OFFSET_MASK 0x0FFF
#define MAX_TRY 10

static u4 getDvmOff(void* handle, char* symbol){
    u1 *addr, *func;
    int i;
    u2 word;

    if (!(addr = (u1*)dlsym(handle, symbol))) {
       XLOGE("failed to get %s", symbol);
       return -1;
    }

    func = (((u4)addr & 0x1) ? (addr - 1) : addr);
    XLOGD("function %s address is 0x%08x", symbol, func);

    for (i = 0; i < MAX_TRY; i++) {
        word = READWORD(func);
        //XLOGD("read opcode = 0x%04x", word);
        if (LDRW_OP_MASK == (word & LDRW_OP_MASK)) {
            return (READWORD(func + 2) & LDRW_OFFSET_MASK);
        }
        func += 2;
    }

   XLOGE("failed to find ldr.w");
   return -1;
}

static u4 showOpCode(void* handle, char* symbol){
    u1 *addr, *func;
    int i;
    u2 word;

    if (!(addr = (u1*)dlsym(handle, symbol))) {
       XLOGE("failed to get %s", symbol);
       return -1;
    }

    func = (((u4)addr & 0x1) ? (addr - 1) : addr);
    XLOGD("function %s address is 0x%08x", symbol, func);
    for (i = 0; i < MAX_TRY; i++) {
        word = READWORD(func);
        XLOGD("read opcode = 0x%04x", word);
        return word;
        func += 2;
    }
}


extern "C" void unpacked(const char* dexFilePath){
    const char *pkgname;
    const char *appclass;
    jboolean iscopy;
    JavaVM *vm;
    void *libdvm;
    void *gdvm;
    HashTable *userDexFiles, *nativeLibs;
    jclass app;
    u4 dvmDexOff, dvmLibOff;
	
	if(dexFilePath == NULL){
		dexFilePath = "/data/local/tmp";
	}else{
		pkgname = dexFilePath;
	}


    if (!(libdvm = dlopen("libdvm.so", 0))) {
        XLOGE("failed to open libdvm.so");
        return;
    }
    if (!(gdvm =dlsym(libdvm, "gDvm"))) {
        XLOGE("gDvm not found");
        return;
    }
    XLOGD("gdvm = 0x%08x", gdvm);
    u4 opcode = showOpCode(libdvm,(char*)"dvmResolveClass");
    if(opcode != 0xe92d){
    	isSecapk = true;
    }
    dvmDexOff = getDvmOff(libdvm,(char*)"_Z25dvmInternalNativeShutdownv");
    userDexFiles = (HashTable *)(*((u4 *)((u1 *)gdvm + dvmDexOff)));
    hashtable_iter(userDexFiles, dex_iter, (char*)pkgname);
    isSecapk = false;
//    dvmLibOff = getDvmOff(libdvm,(char*)"_Z17dvmNativeShutdownv");
//    nativeLibs = (HashTable *)(*((u4 *)((u1 *)gdvm + dvmLibOff)));
//    hashtable_iter(nativeLibs, lib_iter, pkgname);
}
