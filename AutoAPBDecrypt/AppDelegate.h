//
//  AppDelegate.h
//  AutoAPBDecrypt
//
//  Created by Andy Vandijck on 26/01/13.
//  Copyright (c) 2013 AnV Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <stdio.h>
#import <fcntl.h>
#import <stdlib.h>
#import <stdint.h>
#import <unistd.h>
#import <sys/types.h>
#import <arpa/inet.h>
#import <copyfile.h>

#import <mach/mach.h>
#import <mach/machine.h>

#import <mach-o/fat.h>
#import <mach-o/loader.h>

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1080
#import <openssl/blowfish.h>
#import <openssl/aes.h>
#endif

#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1080
#import <CommonCrypto/CommonCryptor.h>
#endif

#define APB_UNPROTECTED_HEADER_SIZE (3 * PAGE_SIZE)
#define APB_FAT_MAX_ARCH                        (5)

#ifndef SG_PROTECTED_VERSION_1
#define SG_PROTECTED_VERSION_1 0x8
#endif /* SG_PROTECTED_VERSION_1 */

static char header_page[PAGE_SIZE];
static char data_page[PAGE_SIZE];
static char xcrypted_page[PAGE_SIZE];

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1080
static boolean_t apb_initialize(int, BF_KEY*);
#endif

static int apb_decrypt_page(const void*, void*);

@interface AppDelegate : NSObject <NSApplicationDelegate>
{
    IBOutlet NSTextField *ProcesPath;
    IBOutlet NSButton *oldBinaries;
    IBOutlet NSProgressIndicator *InProgress;
    NSString *inDir;
    NSString *outDir32;
    NSString *outDir64;
    NSString *outDirUB;
    NSString *outFile32;
    NSString *outFile64;
    NSString *outFileUB;
	NSString *curDirFileName;
    NSOpenPanel *inPanel;
    NSMutableArray *inFiles;
	NSArray *inDirFiles;
	NSArray *inDirs;
    NSLock *lock;
    NSAlert *alert;
    NSThread *workthread;
    unsigned long currentDirNum;
    unsigned long currentFileInDirNum;
    unsigned long inFilesCount;
    unsigned short subDirCount;
    BOOL currentDirFileIsDir;
    BOOL decryptOld;
    unsigned long currentFileInDirNumBackup[65535];
	unsigned long currentDirNumBackup[65535];
	NSArray *inDirFilesBackup[65535];
    BOOL busy;
    BOOL secondpass;
}

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1080
-(BOOL)apb_initialize:(BF_KEY *)key, aesctx1:(aes_decrypt_ctx *)ctx1 aesctx2:(aes_decrypt_ctx *)ctx2;
#endif

-(int)apb_decrypt_page:(const void *)in out:(void *)out;

-(int)DecryptFile32:(NSString *)fIn output:(NSString *)fOut;
-(int)DecryptFile64:(NSString *)fIn output:(NSString *)fOut;
-(void)setOutDirs;
-(void)RecursiveHandle:(NSArray *)pt;
-(IBAction)setInDirectory:(id)sender;
-(IBAction)runDecrypt:(id)sender;

@end
