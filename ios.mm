//
//  ios.cpp
//  DateTimeLib
//
//  Created by Alexander Kormanovsky on 12.08.16.
//  Copyright © 2016 Alexander Kormanovsky. All rights reserved.
//

#if HAS_IOS

#include "ios.h"
#include "NVHTarGzip.h"

#define EXTENSION   "tar.gz"
#define DIR_NAME    "tzdata"

std::string ankorm::iOSUtils::get_tzdata_path()
{
    static NSString *result = @"";
    NSFileManager *manager = [NSFileManager defaultManager];
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        NSArray *paths = [NSBundle pathsForResourcesOfType:@EXTENSION inDirectory:[[NSBundle mainBundle] bundlePath]];
        
        if (paths.count != 0) {
            NSString *archivePath = paths[0];
            NSURL *docsURL = [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                                                     inDomains:NSUserDomainMask] lastObject];
            
            NSString *path = [[docsURL URLByAppendingPathComponent:@DIR_NAME] path];
            
            if ([manager fileExistsAtPath:path]) {
                result = path;
                return;
            }
            
            [manager createDirectoryAtPath:path withIntermediateDirectories:NO attributes:nil error:nil];
            
            NSError *error;
            
            [[NVHTarGzip sharedInstance] unTarGzipFileAtPath:archivePath toPath:path error:&error];
            
            if (error != nil) {
                NSLog(@"%s Error extracting %@", __func__, error);
            } else {
                result = path;
            }
            
        }
    });
    
    return [result UTF8String];
}

#endif