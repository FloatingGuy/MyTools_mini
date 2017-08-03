/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// OpenGL ES 2.0 code
#define LOG_TAG "introspy"
#include <jni.h>
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
#include "object.h"
#include "dvmMethod.h"

using android::AndroidRuntime;
static const void dexFindMethodInsns(const DexFile *dexFile, const DexClassData*classData,int classDataOff);
void append_dump_file(void *start, int size);
static const DexCode* dexGetCode(const DexFile* pDexFile,const DexMethod* pDexMethod);
static int readAndVerifyUnsignedLeb128(const u1** pStream, const u1* limit,bool* okay);
static void dumpDexCode(const DexCode *pCode);
size_t (*dexGetDexCodeSize)(const DexCode* pCode);
static DexFile gDexFile;
JNIEnv* env;
u4 gSize;
u1* forkDex;
bool packedType = false;
char* path;

static jmethodID jmethod;
static jclass jbaiduClazz = NULL;
static jmethodID jmethod_d = NULL;
static jobject classLoader;
static jmethodID loadClass;
jclass classObj;
jclass find_class(char* className){
	if(classObj != NULL)
		env->DeleteLocalRef(classObj);
	int i;
	int size;
	jobject values;
	static jclass clazzHashMap;
	jobject objLoaders;
	jfieldID fieldLoaders;
	jobject objApplicationLoaders;
	jclass clazzCL;
	jobjectArray classLoaders;
	jmethodID methodToArray;
	static jclass clazzValues;
	jstring param = env->NewStringUTF(className);
	jfieldID fieldApplicationLoaders;
	if(classLoader !=NULL && loadClass != NULL){
		goto invoke_label;
	}
	//XLOGD("goto ApplicationLoaders");
	static jclass  clazzApplicationLoaders = env->FindClass("android/app/ApplicationLoaders");
	if(clazzApplicationLoaders != NULL){
		fieldApplicationLoaders = env->GetStaticFieldID(clazzApplicationLoaders, "gApplicationLoaders","Landroid/app/ApplicationLoaders;");
		objApplicationLoaders = env->GetStaticObjectField(clazzApplicationLoaders, fieldApplicationLoaders);
		fieldLoaders = env->GetFieldID(clazzApplicationLoaders,"mLoaders", "Ljava/util/Map;");
		objLoaders = env->GetObjectField(objApplicationLoaders,fieldLoaders);
		clazzHashMap = env->GetObjectClass(objLoaders);
		static jmethodID methodValues = env->GetMethodID(clazzHashMap, "values","()Ljava/util/Collection;");
		values = env->CallObjectMethod(objLoaders, methodValues);
		if(values != NULL){
			clazzValues = env->GetObjectClass(values);
			methodToArray = env->GetMethodID(clazzValues,"toArray", "()[Ljava/lang/Object;");
			if(methodToArray == NULL)
				return NULL;
			classLoaders = (jobjectArray) env->CallObjectMethod(values,methodToArray);
			env->ExceptionClear();
			size = env->GetArrayLength(classLoaders);
			for (i = 0; i < size; i++) {
				classLoader = env->GetObjectArrayElement(classLoaders,i);
				if(classLoader == NULL)
					continue;
				clazzCL = env->GetObjectClass(classLoader);
				loadClass = env->GetMethodID(clazzCL, "loadClass","(Ljava/lang/String;)Ljava/lang/Class;");
				env->DeleteLocalRef(clazzCL);
				env->DeleteLocalRef(classLoaders);
				env->DeleteLocalRef(clazzHashMap);
				env->DeleteLocalRef(objLoaders);
				env->DeleteLocalRef(objApplicationLoaders);
				//env->DeleteLocalRef(clazzApplicationLoaders);
invoke_label:
				classObj = (jclass)env->CallObjectMethod(classLoader, loadClass,param);
				if (classObj != NULL && (u4)classObj & 0x03 != 0) {
					break;
				}
			}
			env->DeleteLocalRef(param);
			if(classObj != NULL){
				//return (jclass) env->NewGlobalRef(classObj);
				return (jclass)(classObj);
			}else{
				XLOGD("not fount found classObj");
				return NULL;
			}
		}
	}else{
		XLOGD("not found ApplicationLoaders");
		return NULL;
	}
}

void inline cacheflush(unsigned int begin, unsigned int end){
	const int syscall = 0xf0002;
	__asm __volatile (
		"mov	 r0, %0\n"
		"mov	 r1, %1\n"
		"mov	 r7, %2\n"
		"mov     r2, #0x0\n"
		"svc     0x00000000\n"
		:
		:	"r" (begin), "r" (end), "r" (syscall)
		:	"r0", "r1", "r7"
		);
}

static char *getString(const DexFile *dexFile, int id){
    return (char *)(dexFile->baseAddr + dexFile->pStringIds[id].stringDataOff+1);
}

static int getTypeIdStringId(const DexFile *dexFile, int id){
    const DexTypeId *typeId = dexFile->pTypeIds;
    return typeId[id].descriptorIdx;
}

#define getTpyeIdString(dexFile, id) getString((dexFile), getTypeIdStringId((dexFile),(id)))

static void getAccessFlags(char *buf, int flags){
    if((flags & ACC_PUBLIC) != 0)   strcat(buf, "public ");
    if((flags & ACC_PRIVATE) != 0)   strcat(buf, "private ");
    if((flags & ACC_PROTECTED) != 0)   strcat(buf, "protected ");    
    if((flags & ACC_STATIC) != 0)   strcat(buf, "static ");    
    if((flags & ACC_FINAL) != 0)   strcat(buf, "final ");    
    if((flags & ACC_SYNCHRONIZED) != 0)   strcat(buf, "synchronized ");    
    if((flags & ACC_SUPER) != 0)   strcat(buf, "super ");    
    if((flags & ACC_VOLATILE) != 0)   strcat(buf, "volatile ");    
    if((flags & ACC_BRIDGE) != 0)   strcat(buf, "bridge ");    
    if((flags & ACC_TRANSIENT) != 0)   strcat(buf, "transient ");    
    if((flags & ACC_VARARGS) != 0)   strcat(buf, "varargs ");    
    if((flags & ACC_NATIVE) != 0)   strcat(buf, "native ");    
    if((flags & ACC_INTERFACE) != 0)   strcat(buf, "interface ");    
    if((flags & ACC_ABSTRACT) != 0)   strcat(buf, "abstract ");    
    if((flags & ACC_STRICT) != 0)   strcat(buf, "strict ");    
    if((flags & ACC_SYNTHETIC) != 0)   strcat(buf, "synthetic ");    
    if((flags & ACC_ANNOTATION) != 0)   strcat(buf, "annotation ");    
    if((flags & ACC_ENUM) != 0)   strcat(buf, "enum ");    
    if((flags & ACC_CONSTRUCTOR) != 0)   strcat(buf, "constructor ");    
    if((flags & ACC_DECLARED_SYNCHRONIZED) != 0)   strcat(buf, "synchronize ");    
}

static int readUnsignedLeb128(const u1** pStream) {
    const u1* ptr = *pStream;
    int result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *pStream = ptr;
    return result;
}

static u1* writeUnsignedLeb128(u1* ptr, u4 data,u4 nnn){
	int num = 0;
    while (true) {
        u1 out = data & 0x7f;
        if (num < nnn) {
            *ptr++ = out | 0x80;
            data >>= 7;
            num++;
        } else {
            *ptr++ = out;
            break;
        }
    }
    return ptr;
}

u1* writeUnsignedLeb128NoNum(u1* ptr, u4 data){
    while (true) {
        u1 out = data & 0x7f;
        if (out != data) {
            *ptr++ = out | 0x80;
            data >>= 7;
        } else {
            *ptr++ = out;
            break;
        }
    }
    return ptr;
}
static const DexCode* dexGetCode(const DexFile* pDexFile,const DexMethod* pDexMethod){
    if (pDexMethod->codeOff == 0)
        return NULL;
    return (const DexCode*) (pDexFile->baseAddr + pDexMethod->codeOff);
}

/* return the ClassDef with the specified index */
static const DexClassDef* dexGetClassDef(const DexFile* pDexFile, u4 idx){
    assert(idx < pDexFile->pHeader->classDefsSize);
    return &pDexFile->pClassDefs[idx];
}


/* Read the header of a class_data_item without verification. This
 * updates the given data pointer to point past the end of the read
 * data. */
static void dexReadClassDataHeader(const u1** pData,DexClassDataHeader *pHeader){
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
    const u1** headerEndAddr = pData;
}

/* Read an encoded_field without verification. This updates the
 * given data pointer to point past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
static void dexReadClassDataField(const u1** pData, DexField* pField,u4* lastIndex){
    u4 index = *lastIndex + readUnsignedLeb128(pData);

    pField->accessFlags = readUnsignedLeb128(pData);
    pField->fieldIdx = index;
    *lastIndex = index;
}

/* Read an encoded_method without verification. This updates the
 * given data pointer to point past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
static void dexReadClassDataMethod(const u1** pData, DexMethod* pMethod,u4* lastIndex,const char* className,jclass clazz) { //add className to decode method param
	u4 index = *lastIndex + readUnsignedLeb128(pData);
	u1* accessFlags_addr = (u1*)*pData;
    pMethod->accessFlags = readUnsignedLeb128(pData);
    u1* codeOff = (u1*)*pData;
    pMethod->codeOff = readUnsignedLeb128(pData);
    u1* endAddr_codeOff = (u1*)*pData;
    pMethod->methodIdx = index;
    char* methodName = getString(&gDexFile, (&gDexFile)->pMethodIds[index].nameIdx);

    u2 protoIdx = (&gDexFile)->pMethodIds[index].protoIdx;
    char methodSignature[1024] = {'\0'};
    const DexProtoId *proto = (&gDexFile)->pProtoIds;
    DexTypeList *plist;
	strcat(methodSignature, "(");
	if(proto[protoIdx].parametersOff != 0){
		plist = (DexTypeList *)((&gDexFile)->baseAddr + proto[protoIdx].parametersOff);
		for(u4 j=0; j<plist->size; j++){
			strcat(methodSignature, getTpyeIdString(&gDexFile,plist->list[j].typeIdx));// param string
		}
	}

	strcat(methodSignature, ")");
	strcat(methodSignature, getTpyeIdString(&gDexFile, proto[protoIdx].returnTypeIdx));// return string

	//ali
    if(pMethod->codeOff > (&gDexFile)->pHeader->fileSize || pMethod->codeOff < 0 ){ //fixed ali packed
	  const DexCode* pCode = dexGetCode(&gDexFile, pMethod);
	  u4 codeDataSize = dexGetDexCodeSize(pCode);
	  u1* codePageAddr = (u1*)((u1*)pCode + codeDataSize);
	  while((u4)codePageAddr%4 != 0){//4 bits align
		  codePageAddr++;
	  }
      //XLOGD(" [MethodIdx:0x%04x,%s->%s][size:%d]",index,className,methodName,(u4)(codePageAddr-(u1*)pCode));
	  append_dump_file((void*)((&gDexFile)->baseAddr+pMethod->codeOff),(u4)(codePageAddr-(u1*)pCode));
	  writeUnsignedLeb128((u1*)((u1*)forkDex+(codeOff-(&gDexFile)->baseAddr)),gSize,(u4)(endAddr_codeOff-codeOff)-1);
	  gSize+=(u4)(codePageAddr-(u1*)pCode);
    }

    //tx  tfd  and Secapk.c
	if(clazz != NULL){
		if(packedType){//Secapk.c
			if(!((pMethod->accessFlags & ACC_ABSTRACT) != 0) && !((pMethod->accessFlags & ACC_NATIVE) != 0)){
				if((pMethod->accessFlags & ACC_STATIC) != 0 ){
					//XLOGD("static env->GetStaticMethodID(clazz,\"%s\",\"%s\")",methodName,buffer);
					jmethod = env->GetStaticMethodID(clazz,methodName,methodSignature);
				}else{
					//XLOGD("no-static env->GetMethodID(clazz,\"%s\",\"%s\")",methodName,buffer);
					jmethod = env->GetMethodID(clazz,methodName,methodSignature);
				}
				env->ExceptionClear();
				const DexCode* pCode = dexGetCode(&gDexFile, pMethod);
				if(pCode != NULL){
					memset((u1*)&(pCode->debugInfoOff)-(&gDexFile)->baseAddr+forkDex,0,4);//clear debugInfoOff
					if(jmethod != NULL){
						Method* method = (Method*)jmethod;
						if(((u4)(method->insns) < (u4)(&gDexFile)->baseAddr) || ((u4)(method->insns) > (u4)((&gDexFile)->baseAddr+gSize))){
							if(pCode != NULL){
								//XLOGI("fixed L%s;->%s%s: copy 0x%08x to 0x%08x,size %d",className,methodName,methodSignature,method->insns,(void*)(pCode->insns),pCode->insnsSize*2);
								memcpy((void*)((u1*)(pCode->insns)-(&gDexFile)->baseAddr+forkDex),method->insns,(pCode->insnsSize)*2);
							}
						}

					}
				}
				jmethod = NULL;
			}
		}else{//tx and tfd
			if(!((pMethod->accessFlags & ACC_ABSTRACT) != 0)){
				if((pMethod->accessFlags & ACC_STATIC) != 0 ){
					//XLOGD("static env->GetStaticMethodID(clazz,\"%s\",\"%s\")",methodName,methodSignature);
					jmethod = env->GetStaticMethodID(clazz,methodName,methodSignature);
				}else{
					//XLOGD("no-static env->GetMethodID(clazz,\"%s\",\"%s\")",methodName,methodSignature);
					jmethod = env->GetMethodID(clazz,methodName,methodSignature);
				}
				env->ExceptionClear();
				if(jmethod != NULL){
					Method* method = (Method*)jmethod;
					if(pMethod->codeOff==0 && (method->accessFlags & ACC_NATIVE) == 0){
							//XLOGI("method L%s;->%s%s: insns address is 0x%08x",className,methodName,methodSignature,method->insns);
							u1* pData = writeUnsignedLeb128NoNum(accessFlags_addr-(&gDexFile)->baseAddr+forkDex,method->accessFlags);
							writeUnsignedLeb128NoNum(pData, (u4)((u1*)(method->insns) - 0x10 - (&gDexFile)->baseAddr));
					}

				}
				jmethod= NULL;
			}
		}
	}

	//baidu @TODO
	if(jbaiduClazz != NULL && jmethod_d != NULL && strcmp(methodName,"onCreate001")==0){
		char baiduparam[1024] = {'\0'};
		snprintf(baiduparam,1024,"L%s;%s",className,(char*)"->onCreate001(Landroid/os/Bundle;)V");
		env->CallStaticVoidMethod(jbaiduClazz,jmethod_d,env->NewStringUTF(baiduparam));
		const DexCode* pCode = dexGetCode(&gDexFile, pMethod);
		u4 codeDataSize = dexGetDexCodeSize(pCode);
		u1* codePageAddr = (u1*)((u1*)pCode + codeDataSize);
		while((u4)codePageAddr%4 != 0){//4 bits align
		  codePageAddr++;
		}
		memcpy(pMethod->codeOff+forkDex,pMethod->codeOff+(&gDexFile)->baseAddr,(u4)(codePageAddr-(u1*)pCode));
		//XLOGI("method L%s;->%s%s fixed",className,methodName,methodSignature);
	}

	if(strcmp(className,"com/baidu/protect/A")==0 && strcmp(methodName,"d")==0){
		//XLOGD("found L%s->;%s%s",className,methodName,methodSignature);
		jbaiduClazz = find_class((char*)className);
		if(jbaiduClazz != NULL){
			jmethod_d = env->GetStaticMethodID(jbaiduClazz,methodName,"(Ljava/lang/String;)V");
		}
	}

    *lastIndex = index;
}



static u1 *getClassDataPtr(const DexFile *dexFile, int idx){
    return (u1 *)(dexFile->baseAddr + dexFile->pClassDefs[idx].classDataOff);
}


static int readAndVerifyUnsignedLeb128(const u1** pStream, const u1* limit,bool* okay){
    const u1* ptr = *pStream;
    int result = readUnsignedLeb128(pStream);

    if (((limit != NULL) && (*pStream > limit))
            || (((*pStream - ptr) == 5) && (ptr[4] > 0x0f))) {
        *okay = false;
    }

    return result;
}

/* Helper for verification which reads and verifies a given number
 * of uleb128 values. */
static bool verifyUlebs(const u1* pData, const u1* pLimit, u4 count){
    bool okay = true;
    u4 i;

    while (okay && (count-- != 0)) {
        readAndVerifyUnsignedLeb128(&pData, pLimit, &okay);
    }

    return okay;
}

/* Read and verify the header of a class_data_item. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure). */
static bool dexReadAndVerifyClassDataHeader(const u1** pData, const u1* pLimit,
        DexClassDataHeader *pHeader) {
    if (! verifyUlebs(*pData, pLimit, 4)) {
        return false;
    }

    dexReadClassDataHeader(pData, pHeader);
    //XLOGD("   ClassHeader: field: s-%ld i-%ld method: d-%ld v-%ld",pHeader->staticFieldsSize, pHeader->instanceFieldsSize,pHeader->directMethodsSize, pHeader->virtualMethodsSize);
    return true;
}

/* Read and verify an encoded_field. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure).
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags or indices
 * are valid. */
static bool dexReadAndVerifyClassDataField(const u1** pData, const u1* pLimit,
        DexField* pField, u4* lastIndex) {
    if (! verifyUlebs(*pData, pLimit, 2)) {
        return false;
    }

    dexReadClassDataField(pData, pField, lastIndex);
    return true;
}

/* Read and verify an encoded_method. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure).
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
static bool dexReadAndVerifyClassDataMethod(const u1** pData, const u1* pLimit,
        DexMethod* pMethod, u4* lastIndex,const char* className,jclass clazz) {
    if (! verifyUlebs(*pData, pLimit, 3)) {
        return false;
    }

    dexReadClassDataMethod(pData, pMethod, lastIndex,className,clazz);
    return true;
}

/* Read, verify, and return an entire class_data_item. This updates
 * the given data pointer to point past the end of the read data. This
 * function allocates a single chunk of memory for the result, which
 * must subsequently be free()d. This function returns NULL if there
 * was trouble parsing the data. If this function is passed NULL, it
 * returns an initialized empty DexClassData structure.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
static DexClassData* dexReadAndVerifyClassData(const u1** pData, const u1* pLimit,const DexFile *dexFile,const char* className,jclass clazz,u4* classDataSize) {
    DexClassDataHeader header;
    u4 lastIndex;
    u4 DexClassData_startAddr,DexClassData_endAddr;

    if (*pData == NULL) {
        DexClassData* result = (DexClassData*) malloc(sizeof(DexClassData));
        memset(result, 0, sizeof(*result));
        return result;
    }

    DexClassData_startAddr = (u4)(u1*)*pData; //start
    if (! dexReadAndVerifyClassDataHeader(pData, pLimit, &header)) {
        return NULL;
    }
    size_t resultSize = sizeof(DexClassData) +
        (header.staticFieldsSize * sizeof(DexField)) +
        (header.instanceFieldsSize * sizeof(DexField)) +
        (header.directMethodsSize * sizeof(DexMethod)) +
        (header.virtualMethodsSize * sizeof(DexMethod));
    DexClassData* result = (DexClassData*) malloc(resultSize);
    u1* ptr = ((u1*) result) + sizeof(DexClassData);
    bool okay = true;
    u4 i;

    if (result == NULL) {
        return NULL;
    }

    result->header = header;

    if (header.staticFieldsSize != 0) {
        result->staticFields = (DexField*) ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    } else {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0) {
        result->instanceFields = (DexField*) ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    } else {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0) {
        result->directMethods = (DexMethod*) ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    } else {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0) {
        result->virtualMethods = (DexMethod*) ptr;

    } else {
        result->virtualMethods = NULL;
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.staticFieldsSize); i++) {
        okay = dexReadAndVerifyClassDataField(pData, pLimit,
                &result->staticFields[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.instanceFieldsSize); i++) {
        okay = dexReadAndVerifyClassDataField(pData, pLimit,
                &result->instanceFields[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.directMethodsSize); i++) {
        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
                &result->directMethods[i], &lastIndex,className,clazz);//add className
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.virtualMethodsSize); i++) {
        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
                &result->virtualMethods[i], &lastIndex,className,clazz);//add className
    }

    DexClassData_endAddr = (u4)(u1*)*pData;//end
    *classDataSize =  DexClassData_endAddr - DexClassData_startAddr;//classDataSize

    if (! okay) {
        free(result);
        return NULL;
    }

    return result;
}

static void dexFindClassData(const DexFile *pDexFile){
    const DexClassDef* classdef;
    u4 count = pDexFile->pHeader->classDefsSize;
    u4 classDataSize = 0;
    const u1* pEncodedData = NULL;
    DexClassData* pClassData = NULL;
    const char *descriptor = NULL;
    char className[1024] = {'\0'};
    jclass clazz;
    jmethodID methodCinit;
    //XLOGD("Class total count: %ld ", count);

    for(u4 i=0; i<count; i++){
        classdef = dexGetClassDef(pDexFile, i);
        if(classdef->classDataOff == 0)
        	continue;
    	memset(className,0,1024);
        descriptor = getTpyeIdString(pDexFile, classdef->classIdx);
    	strncpy(className,descriptor+1,strlen(descriptor)-2);

    	// tx and payegis
        if(className != NULL && strstr(className,"android/support") == NULL
        		&& ((DexHeader*)((&gDexFile)->baseAddr))->fileSize > (((DexHeader*)((&gDexFile)->baseAddr))->dataOff+((DexHeader*)((&gDexFile)->baseAddr))->dataSize)
        		&& strncmp((char*)(((DexHeader*)((&gDexFile)->baseAddr))->magic), "dex\n035\0", 8)==0
        		&& !((classdef->accessFlags & ACC_INTERFACE) != 0)){
        	clazz = find_class(className);
        	env->ExceptionClear();
        	if(clazz != NULL && (u4)clazz & 0x03 != 0){
        		methodCinit = env->GetStaticMethodID(clazz,"<clinit>","()V");
        		if((methodCinit != NULL)){
        			env->CallStaticVoidMethod(clazz,methodCinit);//clinit
        		}
                methodCinit = NULL;
        	}else{
        		//XLOGE("className:%s===0x%08x, %d",className,(u4)clazz,(u4)clazz & 0x03);
        		clazz = NULL;
        	}
        	env->ExceptionClear();
        }else{
        	clazz = NULL;
        }

        //Bangcle Enterprise Edition ...
        if(packedType && strstr(className,"android/support") == NULL && !((classdef->accessFlags & ACC_INTERFACE) != 0)){
        	clazz = find_class(className);
        	env->ExceptionClear();
        	if(clazz != NULL && (u4)clazz & 0x03 != 0){

        	}else{
        		//XLOGE("className:%s===0x%08x, %d",className,(u4)clazz,(u4)clazz & 0x03);
        		clazz = NULL;
        	}
        	env->ExceptionClear();
        }

        pEncodedData = pDexFile->baseAddr + classdef->classDataOff;
        pClassData = dexReadAndVerifyClassData(&pEncodedData,NULL,pDexFile,className,clazz,&classDataSize);

        clazz = NULL;

        ////old 360 and baidu
        if(classdef->classDataOff > ((DexHeader*)((&gDexFile)->baseAddr))->fileSize || classdef->classDataOff < 0){
        	//XLOGI("====>Found Class %s,classDataOff:0x%08x,data size:%d", descriptor,classdef->classDataOff,classDataSize);
			append_dump_file((void*)(classdef->classDataOff+pDexFile->baseAddr),classDataSize);
			u4* classData_addr =(u4*)(&(classdef->classDataOff)) + ((u4*)forkDex - (u4*)(pDexFile->baseAddr));
			*(u4*)classData_addr = gSize;//replace classDataOff
			if(*(u4*)classData_addr != gSize){
				XLOGE("replace error!");
			}
			if(classDataSize>0){
				gSize += classDataSize;
			}
        	classDataSize = 0;
        }

        if (pClassData == NULL) {
            XLOGE("Trouble reading class data (#%ld) for %s\n", i, descriptor);
            continue;
        }
        free(pClassData);
    }
    classLoader = NULL;
}

void append_dump_file(void *start, int size){
    int fd;
    if (-1 == (fd = open(path,  O_APPEND | O_CREAT | O_RDWR , 0666))) {
       XLOGE("open %s failed.", path);
       return ;
    }
    if (size != write(fd, start, size)) {
    		XLOGE("write %s failed",path);
    }
    close(fd);
}

void dump_file(void* start, int size){
    int fd;
    if (-1 == (fd = open(path,O_RDWR|O_CREAT, 0666))) {
       XLOGE("open %s failed.", path);
       return;
    }
    if ((1 != write(fd,start,1))||(size != write(fd,(void*)((u1*)start+1),size-1)+1)) { //bypass hook write
       XLOGE("write %s failed.", path);
    }
    close(fd);
}


static void handleDexMethod(DexClassData* classData, const char*method){
	// TODO
}

static const void dexFindClassMethod(DexFile *dexFile){
	dexFindClassData(dexFile);
}

static void fixDexHeader(DexHeader* pDexHeader){
	memcpy(pDexHeader->magic,"dex\n035",7);
	pDexHeader->stringIdsOff = 0x00000070;
	pDexHeader->typeIdsOff = pDexHeader->stringIdsOff + (u4)(4*(pDexHeader->stringIdsSize));
	pDexHeader->protoIdsOff = pDexHeader->typeIdsOff + (u4)(4*(pDexHeader->typeIdsSize));
	pDexHeader->fieldIdsOff = pDexHeader->protoIdsOff + (u4)(0x0C*(pDexHeader->protoIdsSize));
	pDexHeader->methodIdsOff = pDexHeader->fieldIdsOff + (u4)(0x08*(pDexHeader->fieldIdsSize));
	pDexHeader->classDefsOff = pDexHeader->methodIdsOff + (u4)(0x08*(pDexHeader->methodIdsSize));
	pDexHeader->fileSize = pDexHeader->dataOff + pDexHeader->dataSize;
}

void nativeParserDex(void* dexBase,int size,bool isSecapk,char* filePath){
	void* libdvm;
	env = android::AndroidRuntime::getJNIEnv();
	packedType = isSecapk;
	path = filePath;
    if (!(libdvm = dlopen("libdvm.so", 0))) {
        XLOGE("failed to open libdvm.so");
        return;
    }

    if (!(dexGetDexCodeSize =(size_t (*)(const DexCode* pCode))dlsym(libdvm, "_Z17dexGetDexCodeSizePK7DexCode"))) { //get dexCode size
        XLOGE("dexGetDexCodeSize not found");
        return;
    }


	forkDex = (u1*)malloc(size);
	memcpy(forkDex,dexBase,size);

	DexHeader *dexHeader = (DexHeader *)forkDex;
    fixDexHeader(dexHeader);
    gDexFile.baseAddr   = (u1*)dexBase;
    gDexFile.pHeader    = dexHeader;
    gDexFile.pStringIds = (DexStringId*)((u4)dexBase+dexHeader->stringIdsOff);
    gDexFile.pTypeIds   = (DexTypeId*)((u4)dexBase+dexHeader->typeIdsOff);
    gDexFile.pMethodIds = (DexMethodId*)((u4)dexBase+dexHeader->methodIdsOff);
    gDexFile.pFieldIds  = (DexFieldId*)((u4)dexBase+dexHeader->fieldIdsOff);
    gDexFile.pClassDefs = (DexClassDef*)((u4)dexBase+dexHeader->classDefsOff);
    gDexFile.pProtoIds  = (DexProtoId*)((u4)dexBase+dexHeader->protoIdsOff);
    gSize = size;//È«¾Ösize
    remove(path);
    dump_file(dexBase,size);
    mprotect(forkDex, size, PROT_READ | PROT_WRITE);
    dexFindClassMethod(&gDexFile);
    cacheflush((u4)forkDex,(u4)(forkDex+size));
    dump_file(forkDex,size);//fixed,replace
    XLOGD("dump to %s,baseAddr:0x%08x,old size:%d,size:%d",path,forkDex,size,gSize);
	XLOGI("---------------------end----------------------");
    free(forkDex);
    gSize = 0;
}
