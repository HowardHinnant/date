//
// The MIT License (MIT)
//
// Copyright (c) 2016 Alexander Kormanovsky
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#include "ios.h"

#if TARGET_OS_IPHONE

#include <Foundation/Foundation.h>

#include <iostream>
#include <zlib.h>
#include <sys/stat.h>

#ifndef TAR_DEBUG
#  define TAR_DEBUG 0
#endif

#define INTERNAL_DIR        "Library"
#define TZDATA_DIR          "tzdata"
#define TARGZ_EXTENSION     "tar.gz"

#define TAR_BLOCK_SIZE                  512
#define TAR_TYPE_POSITION               156
#define TAR_NAME_POSITION               0
#define TAR_NAME_SIZE                   100
#define TAR_SIZE_POSITION               124
#define TAR_SIZE_SIZE                   12

namespace date
{
namespace iOSUtils
{

struct TarInfo
{
    char objType;
    std::string objName;
    int64_t realContentSize; // writable size without padding zeroes
    int64_t blocksContentSize; // adjusted size to 512 bytes blocks
    bool success;
};

std::string convertCFStringRefPathToCStringPath(CFStringRef ref);
bool extractTzdata(CFURLRef homeUrl, CFURLRef archiveUrl, std::string destPath);
TarInfo getTarObjectInfo(CFReadStreamRef readStream, int64_t location);
std::string getTarObject(CFReadStreamRef readStream, int64_t size);
bool writeFile(CFURLRef tzdataUrl, std::string fileName, std::string data,
               int64_t realContentSize);
    
std::string
get_current_timezone()
{
    CFTimeZoneRef tzRef = CFTimeZoneCopySystem();
    CFStringRef tzNameRef = CFTimeZoneGetName(tzRef);
    CFIndex bufferSize = CFStringGetLength(tzNameRef) + 1;
    char buffer[bufferSize];
    
    if (CFStringGetCString(tzNameRef, buffer, bufferSize, kCFStringEncodingUTF8))
    {
        CFRelease(tzRef);
        return std::string(buffer);
    }
    
    CFRelease(tzRef);
    
    return "";
}

std::string
get_tzdata_path()
{
    CFURLRef homeUrlRef = CFCopyHomeDirectoryURL();
    CFStringRef homePath = CFURLCopyPath(homeUrlRef);
    std::string path(std::string(convertCFStringRefPathToCStringPath(homePath)) +
                     INTERNAL_DIR + "/" + TZDATA_DIR);
    std::string result_path(std::string(convertCFStringRefPathToCStringPath(homePath)) +
                     INTERNAL_DIR);
    
    if (access(path.c_str(), F_OK) == 0)
    {
#if TAR_DEBUG
        printf("tzdata dir exists\n");
#endif
        CFRelease(homeUrlRef);
        CFRelease(homePath);
        
        return result_path;
    }

    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFArrayRef paths = CFBundleCopyResourceURLsOfType(mainBundle, CFSTR(TARGZ_EXTENSION),
                                                      NULL);

    if (CFArrayGetCount(paths) != 0)
    {
        // get archive path, assume there is no other tar.gz in bundle
        CFURLRef archiveUrl = static_cast<CFURLRef>(CFArrayGetValueAtIndex(paths, 0));
        CFStringRef archiveName = CFURLCopyPath(archiveUrl);
        archiveUrl = CFBundleCopyResourceURL(mainBundle, archiveName, NULL, NULL);
        
        extractTzdata(homeUrlRef, archiveUrl, path);
        
        CFRelease(archiveUrl);
        CFRelease(archiveName);
    }
    
    CFRelease(homeUrlRef);
    CFRelease(homePath);
    CFRelease(paths);

    return result_path;
}
        
std::string
convertCFStringRefPathToCStringPath(CFStringRef ref)
{
    CFIndex bufferSize = CFStringGetMaximumSizeOfFileSystemRepresentation(ref);
    char *buffer = new char[bufferSize];
    CFStringGetFileSystemRepresentation(ref, buffer, bufferSize);
    auto result = std::string(buffer);
    delete[] buffer;
    return result;
}
        
bool extractTzdata(CFURLRef homeUrl, CFURLRef archiveUrl, std::string destPath)
{
    const char *TAR_TMP_PATH = "/tmp.tar";

    // create Library path
    CFStringRef libraryStr = CFStringCreateWithCString(NULL, INTERNAL_DIR,
                                                       CFStringGetSystemEncoding());
    CFURLRef libraryUrl = CFURLCreateCopyAppendingPathComponent(kCFAllocatorDefault,
                                                                homeUrl, libraryStr,
                                                                false);

    // create tzdata path
    CFStringRef tzdataPathRef = CFStringCreateWithCString(NULL, std::string(std::string(INTERNAL_DIR) + "/" + TZDATA_DIR).c_str(),
                                                          CFStringGetSystemEncoding());
    CFURLRef tzdataPathUrl = CFURLCreateCopyAppendingPathComponent(NULL, homeUrl,
                                                                   tzdataPathRef, false);

    // create src archive path
    CFStringRef archivePath = CFURLCopyPath(archiveUrl);
    gzFile tarFile = gzopen(convertCFStringRefPathToCStringPath(archivePath).c_str(), "rb");

    // create tar unpacking path
    CFStringRef tarName = CFStringCreateWithCString(NULL, TAR_TMP_PATH,
                                                    CFStringGetSystemEncoding());
    CFURLRef tarUrl = CFURLCreateCopyAppendingPathComponent(NULL, libraryUrl, tarName,
                                                            false);
    CFStringRef tarPathRef = CFURLCopyPath(tarUrl);
    auto tarPath = convertCFStringRefPathToCStringPath(tarPathRef);
    
    // create tzdata directory
    mkdir(destPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    // create stream
    CFWriteStreamRef writeStream = CFWriteStreamCreateWithFile(NULL, tarUrl);
    bool success = true;
    
    CFRelease(libraryStr);
    CFRelease(libraryUrl);
    CFRelease(tzdataPathRef);
    CFRelease(archivePath);
    CFRelease(tarName);
    CFRelease(tarPathRef);

    if (!CFWriteStreamOpen(writeStream))
    {
        CFStreamError err = CFWriteStreamGetError(writeStream);

        if (err.domain == kCFStreamErrorDomainPOSIX)
        {
            printf("kCFStreamErrorDomainPOSIX %i\n", err.error);
        }
        else if(err.domain == kCFStreamErrorDomainMacOSStatus)
        {
            printf("kCFStreamErrorDomainMacOSStatus %i\n", err.error);
        }
        
        success = false;
    }

    if (!success)
    {
        CFRelease(tarUrl);
        CFRelease(tzdataPathUrl);
        CFRelease(writeStream);
        return false;
    }

    // ======= extract tar ========

    unsigned int bufferLength = 1024 * 256;  // 256Kb
    void *buffer = malloc(bufferLength);

    while (true)
    {
        int readBytes = gzread(tarFile, buffer, bufferLength);

        if (readBytes > 0)
        {
            CFIndex writtenBytes = CFWriteStreamWrite(writeStream, (unsigned char*)buffer,
                                                      readBytes);
            
            if (writtenBytes < 0)
            {
                CFStreamError err = CFWriteStreamGetError(writeStream);
                printf("write stream error %i\n", err.error);
                success = false;
                break;
            }
        }
        else if (readBytes == 0)
        {
            break;
        }
        else if  (readBytes == -1)
        {
            printf("decompression failed\n");
            success = false;
            break;
        }
        else
        {
            printf("unexpected zlib state\n");
            success = false;
            break;
        }
    }

    CFWriteStreamClose(writeStream);
    CFRelease(writeStream);
    free(buffer);
    gzclose(tarFile);

    if (!success)
    {
        CFRelease(tarUrl);
        CFRelease(tzdataPathUrl);
        return false;
    }

    // ======== extract files =========

    uint64_t location = 0; // Position in the file

    // get file size
    struct stat stat_buf;
    int res = stat(tarPath.c_str(), &stat_buf);
    if (res != 0)
    {
        printf("error file size\n");
        CFRelease(tarUrl);
        CFRelease(tzdataPathUrl);
        return false;
    }
    int64_t tarSize = stat_buf.st_size;

    // create read stream
    CFReadStreamRef readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault, tarUrl);
    CFRelease(tarUrl);

    if (!CFReadStreamOpen(readStream))
    {
        CFStreamError err = CFReadStreamGetError(readStream);
        
        if (err.domain == kCFStreamErrorDomainPOSIX)
        {
            printf("kCFStreamErrorDomainPOSIX %i", err.error);
        }
        else if(err.domain == kCFStreamErrorDomainMacOSStatus)
        {
            printf("kCFStreamErrorDomainMacOSStatus %i", err.error);
        }
        
        success = false;
    }

    if (!success)
    {
        CFRelease(tzdataPathUrl);
        CFRelease(readStream);
        return false;
    }

    // process files
    while (location < tarSize)
    {
        TarInfo info = getTarObjectInfo(readStream, location);

        if (!info.success || info.realContentSize == 0)
        {
            break; // something wrong or all files are read
        }

        switch (info.objType)
        {
            case '0':   // file
            case '\0':  //
            {
                std::string obj = getTarObject(readStream, info.blocksContentSize);
#if TAR_DEBUG
                size += info.realContentSize;
                printf("#%i %s file size %lld written total %ld from %lld\n", ++count,
                       info.objName.c_str(), info.realContentSize, size, tarSize);
#endif
                writeFile(tzdataPathUrl, info.objName, obj, info.realContentSize);
                location += info.blocksContentSize;

                break;
            }
        }
    }
    
    CFRelease(tzdataPathUrl);
    CFReadStreamClose(readStream);
    CFRelease(readStream);
    
    return true;
}
        
TarInfo
getTarObjectInfo(CFReadStreamRef readStream, int64_t location)
{
    int64_t length = TAR_BLOCK_SIZE;
    uint8_t buffer[length];

    char type;
    char name[TAR_NAME_SIZE + 1];
    char sizeBuf[TAR_SIZE_SIZE + 1];
    CFIndex bytesRead;

    bytesRead = CFReadStreamRead(readStream, buffer, length);

    if (bytesRead < 0)
    {
        CFStreamError err = CFReadStreamGetError(readStream);
        printf("error reading tar object info %i", err.error);
        return {false};
    }

    memcpy(&type, &buffer[TAR_TYPE_POSITION], 1);

    memset(&name, '\0', TAR_NAME_SIZE + 1);
    memcpy(&name, &buffer[TAR_NAME_POSITION], TAR_NAME_SIZE);

    memset(&sizeBuf, '\0', TAR_SIZE_SIZE + 1);
    memcpy(&sizeBuf, &buffer[TAR_SIZE_POSITION], TAR_SIZE_SIZE);
    int64_t realSize = strtol(sizeBuf, NULL, 8);
    int64_t blocksSize = realSize + (TAR_BLOCK_SIZE - (realSize % TAR_BLOCK_SIZE));

    return {type, std::string(name), realSize, blocksSize, true};
}

std::string
getTarObject(CFReadStreamRef readStream, int64_t size)
{
    uint8_t buffer[size];

    CFIndex bytesRead = CFReadStreamRead(readStream, buffer, size);

    if (bytesRead < 0)
    {
        CFStreamError err = CFReadStreamGetError(readStream);
        printf("error reading tar object info %i", err.error);
    }

    return std::string((char *)buffer);
}

bool
writeFile(CFURLRef tzdataUrl, std::string fileName, std::string data,
          int64_t realContentSize)
{
    // create stream
    CFStringRef fileNameRef = CFStringCreateWithCString(NULL, fileName.c_str(),
                                                        CFStringGetSystemEncoding());
    CFURLRef url = CFURLCreateCopyAppendingPathComponent(NULL, tzdataUrl, fileNameRef,
                                                         false);
    CFWriteStreamRef writeStream = CFWriteStreamCreateWithFile(NULL, url);
    
    CFRelease(fileNameRef);
    CFRelease(url);

    // open stream
    if (!CFWriteStreamOpen(writeStream))
    {
        CFStreamError err = CFWriteStreamGetError(writeStream);

        if (err.domain == kCFStreamErrorDomainPOSIX)
        {
            printf("kCFStreamErrorDomainPOSIX %i\n", err.error);
        }
        else if(err.domain == kCFStreamErrorDomainMacOSStatus)
        {
            printf("kCFStreamErrorDomainMacOSStatus %i\n", err.error);
        }

        CFRelease(writeStream);
        return false;
    }

    // trim empty space
    uint8_t trimmedData[realContentSize + 1];
    memset(&trimmedData, '\0', realContentSize);
    memcpy(&trimmedData, data.c_str(), realContentSize);

    // write
    CFIndex writtenBytes = CFWriteStreamWrite(writeStream, trimmedData, realContentSize);

    if (writtenBytes < 0)
    {
        CFStreamError err = CFWriteStreamGetError(writeStream);
        printf("write stream error %i\n", err.error);
    }

    CFWriteStreamClose(writeStream);
    CFRelease(writeStream);
    writeStream = NULL;

    return true;
}

}  // namespace iOSUtils
}  // namespace date

#endif  // TARGET_OS_IPHONE
