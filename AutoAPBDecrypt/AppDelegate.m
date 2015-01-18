//
//  AppDelegate.m
//  AutoAPBDecrypt
//
//  Created by Andy Vandijck on 26/01/13.
//  Copyright (c) 2013 AnV Software. All rights reserved.
//

#import "AppDelegate.h"

@implementation AppDelegate

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1080
-(BOOL)apb_initialize:(BF_KEY *)key, aesctx1:(aes_decrypt_ctx *)ctx1 aesctx2:(aes_decrypt_ctx *)ctx2
{
    BOOL result = NO;

    static const unsigned char plain_key [65] = "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc";

	BF_set_key(key, 64, plain_key);
    aes_decrypt_key(plain_key, 0x100, ctx1);
    aes_decrypt_key(plain_key + 0x20, 0x100, ctx2);

    result = YES;

    return result;
}
#endif

-(int)apb_decrypt_page:(const void *)in out:(void *)out
{
    const unsigned char *_in = (const unsigned char*)in;
    unsigned char *_out = (unsigned char*)out;
    unsigned char null_ivec[32] = {0,};
    unsigned char aes_ivec[16] = {0,};

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1080
    static BF_KEY key;
    aes_decrypt_ctx ctx1;
    aes_decrypt_ctx ctx2;
    static boolean_t initialized = FALSE;

    if (initialized == FALSE) {
        initialized = [self apb_initialize:&key aesctx1:&ctx1 aesctx2:&ctx2];
        if (initialized == FALSE) {
            return -1;
        }
    }
#else
    static const unsigned char plain_key [65] = "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc";
    size_t data_out = 0;
#endif

#if MAC_OS_X_VERSION_MIN_REQUIRED < 1080
    if (decryptOld == YES)
    {
        aes_decrypt_cbc ((unsigned char *) in, null_ivec, 0x80, (unsigned char *)out, &ctx1);
        aes_decrypt_cbc ((unsigned char *) in + 0x800, null_ivec, 0x80, (unsigned char *)out + 0x800, &ctx2);
    } else {
        BF_cbc_encrypt(_in, _out, PAGE_SIZE, &key, null_ivec, BF_DECRYPT);
    }
#else
    if (decryptOld == YES)
    {
        memset(aes_ivec, 0, sizeof(aes_ivec));
        CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, plain_key, kCCKeySizeAES256, aes_ivec, _in, (PAGE_SIZE / 2), _out,  (PAGE_SIZE / 2), &data_out);
        CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, plain_key + 32, kCCKeySizeAES256, aes_ivec, _in + (PAGE_SIZE / 2), (PAGE_SIZE / 2), _out + (PAGE_SIZE / 2),  (PAGE_SIZE / 2), &data_out);
    } else {
        CCCrypt(kCCDecrypt, kCCAlgorithmBlowfish, 0, plain_key, 64, null_ivec, _in, PAGE_SIZE, _out, PAGE_SIZE, &data_out);
    }
#endif
    
    return 0;
}

- (void)dealloc
{
    [super dealloc];
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
}

-(int)DecryptFile32:(NSString *)fIn output:(NSString *)fOut
{
    int fd_in = -1;
    int fd_out = -1;

    fd_in = open([fIn cStringUsingEncoding:NSUTF8StringEncoding], O_RDONLY);
    if (fd_in < 0) {
        return(-1);
    }

    off_t base = (off_t)0;
    off_t ebase_begin = (off_t)0;
    off_t ebase_end = (off_t)0;
    uint32_t n = 0;
    int ret = 0;
    BOOL foundBin = NO;
    
    ssize_t nbytes = pread(fd_in, header_page, PAGE_SIZE, (off_t)0);
    if (nbytes != PAGE_SIZE) {
        ret = -1;
        goto out;
    }
    
    uint32_t magic = *(uint32_t*)header_page;
    struct mach_header* mh = (struct mach_header*)0;

#ifdef __LITTLE_ENDIAN__
    if (magic == FAT_CIGAM) {
        struct fat_header* fh = (struct fat_header*)header_page;
        uint32_t nfat_arch = ntohl(fh->nfat_arch);
        if (nfat_arch > APB_FAT_MAX_ARCH) {
            ret = -1;
            goto out;
        }
        struct fat_arch* fa = (struct fat_arch*)((char*)header_page + sizeof(struct fat_header));
        for (n = 0; n < nfat_arch; n++, fa++) {
            if (ntohl(fa->cputype) == CPU_TYPE_X86) {
                base = (off_t)ntohl(fa->offset);
                nbytes = pread(fd_in, header_page, PAGE_SIZE, base);
                if (nbytes != PAGE_SIZE) {
                    ret = -1;
                    goto out;
                }
                mh = (struct mach_header*)header_page;
                if (mh->magic != MH_MAGIC)
                {
                    ret = 0;
                    goto out;
                } else {
                    if (mh->cputype != CPU_TYPE_X86) {
                        ret = 0;
                        goto out;
                    } else {
                        foundBin = YES;
                    }
                }
                break;
            }
        }
    } else if (magic == MH_MAGIC) {
        mh = (struct mach_header*)header_page;
        if (mh->cputype != CPU_TYPE_X86) {
            ret = 0;
            goto out;
        } else {
            foundBin = YES;
        }
	} else {
        ret = 0;
        goto out;
    }
#else
#error This file can only be compiled on Intel.
#endif

    if (foundBin == NO)
    {
        ret = 0;
        goto out;
    }

    //printf("Current file: %s\n", [fIn cStringUsingEncoding:NSUTF8StringEncoding]);

    struct segment_command* text = (struct segment_command*)0;
    uint32_t ncmds = 0;
    struct load_command* lc = (struct load_command*)0;
    ncmds = mh->ncmds;
    lc = (struct load_command*)((char*)mh + sizeof(struct mach_header));
    for (n = 0; n < ncmds; n++) {
        if (lc->cmd == LC_SEGMENT) {
            struct segment_command* sc = (struct segment_command*)lc;
            if (strncmp(sc->segname, SEG_TEXT, 6) == 0) {
                text = sc;
                break;
            }
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    if (text == (struct segment_command *)0) {
        ret = 0;
        goto out;
    }

    off_t archbase_begin = (off_t)0;
	off_t archbase_end = (off_t)0;

    if (text->flags ^ SG_PROTECTED_VERSION_1) {
        ret = 0;
        goto out;
    }
    
    archbase_begin = (off_t)(text->fileoff + APB_UNPROTECTED_HEADER_SIZE);
    archbase_end = archbase_begin + (off_t)(text->filesize - APB_UNPROTECTED_HEADER_SIZE);
    ebase_begin = base + archbase_begin;
    ebase_end = base + archbase_end;

    fd_out = open([fOut cStringUsingEncoding:NSUTF8StringEncoding], O_RDWR | O_CREAT | O_EXCL, 0755);
    if (fd_out < 0) {
        ret = -1;
        goto out;
    }

    ret = fcopyfile(fd_in, fd_out, (copyfile_state_t)0, COPYFILE_ALL);
    if (ret) {
        ret = -1;
        goto out;
    }

    text->flags ^= SG_PROTECTED_VERSION_1;

    nbytes = pwrite(fd_out, header_page, PAGE_SIZE, base);
    if (nbytes != PAGE_SIZE) {
        ret = -1;
        goto out;
    }

    off_t count = ebase_end - ebase_begin;
    if (count % PAGE_SIZE) {
        ret = -1;
        goto out;
    }

    while (count > 0) {
        nbytes = pread(fd_in, data_page, PAGE_SIZE, ebase_begin);
        if (nbytes != PAGE_SIZE) {
            ret = -1;
            goto out;
        }
        ret = [self apb_decrypt_page:data_page out:xcrypted_page];
        if (ret) {
            goto out;
        }
        nbytes = pwrite(fd_out, xcrypted_page, PAGE_SIZE, ebase_begin);
        if (nbytes != PAGE_SIZE) {
            ret = -1;
            goto out;
        }
        ebase_begin += (off_t)PAGE_SIZE;
        count -= (off_t)PAGE_SIZE;
    }

    ret = 1;

out:
    if (fd_in >= 0) {
        close(fd_in);
    }
    if (fd_out >= 0) {
        close(fd_out);
        if (ret <= 0) {
            unlink([fOut cStringUsingEncoding:NSUTF8StringEncoding]);
        }
    }
    
    return(ret);
}

-(int)DecryptFile64:(NSString *)fIn output:(NSString *)fOut
{
    int fd_in = -1;
    int fd_out = -1;
    
    fd_in = open([fIn cStringUsingEncoding:NSUTF8StringEncoding], O_RDONLY);
    if (fd_in < 0) {
        return(-1);
    }
    
    off_t base = (off_t)0;
    off_t ebase_begin = (off_t)0;
    off_t ebase_end = (off_t)0;
    uint32_t n = 0;
    int ret = 0;
    BOOL foundBin = NO;
    
    ssize_t nbytes = pread(fd_in, header_page, PAGE_SIZE, (off_t)0);
    if (nbytes != PAGE_SIZE) {
        ret = -1;
        goto out;
    }
    
    uint32_t magic = *(uint32_t*)header_page;
    struct mach_header_64* mh64 = (struct mach_header_64*)0;
    
#ifdef __LITTLE_ENDIAN__
    if (magic == FAT_CIGAM) {
        struct fat_header* fh = (struct fat_header*)header_page;
        uint32_t nfat_arch = ntohl(fh->nfat_arch);
        if (nfat_arch > APB_FAT_MAX_ARCH) {
            ret = -1;
            goto out;
        }
        struct fat_arch* fa = (struct fat_arch*)((char*)header_page + sizeof(struct fat_header));
        for (n = 0; n < nfat_arch; n++, fa++) {
            if (ntohl(fa->cputype) == CPU_TYPE_X86_64) {
                base = (off_t)ntohl(fa->offset);
				nbytes = pread(fd_in, header_page, PAGE_SIZE, base);
                if (nbytes != PAGE_SIZE) {
                    ret = -1;
                    goto out;
                }
				mh64 = (struct mach_header_64*)header_page;
                if (mh64->magic != MH_MAGIC_64)
                {
                    ret = 0;
                    goto out;
                } else {
                    if (mh64->cputype != CPU_TYPE_X86_64) {
                        ret = 0;
                        goto out;
                    } else {
                        foundBin = YES;
                    }
                }
				break;
            }
        }
    } else if (magic == MH_MAGIC_64) {
		mh64 = (struct mach_header_64*)header_page;
        if (mh64->cputype != CPU_TYPE_X86_64) {
            ret = 0;
            goto out;
        } else {
            foundBin = YES;
        }
    } else {
        ret = 0;
        goto out;
    }
#else
#error This file can only be compiled on Intel.
#endif

    if (foundBin == NO)
    {
        ret = 0;
        goto out;
    }

    struct segment_command_64* text64 = (struct segment_command_64 *)0;
    uint32_t ncmds = 0;
    struct load_command* lc = (struct load_command*)0;

    ncmds = mh64->ncmds;
    lc = (struct load_command*)((char*)mh64 + sizeof(struct mach_header_64));
    for (n = 0; n < ncmds; n++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64* sc64 = (struct segment_command_64*)lc;
            if (strncmp(sc64->segname, SEG_TEXT, 6) == 0) {
                text64 = sc64;
                break;
            }
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    if (text64 == (struct segment_command_64 *)0) {
        ret = 0;
        goto out;
    }
    
    off_t archbase_begin = (off_t)0;
	off_t archbase_end = (off_t)0;
    
    if (text64->flags ^ SG_PROTECTED_VERSION_1) {
        ret = 0;
        goto out;
    }
    
    archbase_begin = (off_t)(text64->fileoff + APB_UNPROTECTED_HEADER_SIZE);
    archbase_end = archbase_begin + (off_t)(text64->filesize - APB_UNPROTECTED_HEADER_SIZE);
    ebase_begin = base + archbase_begin;
    ebase_end = base + archbase_end;
    
    fd_out = open([fOut cStringUsingEncoding:NSUTF8StringEncoding], O_RDWR | O_CREAT | O_EXCL, 0755);
    if (fd_out < 0) {
        ret = -1;
        goto out;
    }
    
    ret = fcopyfile(fd_in, fd_out, (copyfile_state_t)0, COPYFILE_ALL);
    if (ret) {
        ret = -1;
        goto out;
    }
    
    text64->flags ^= SG_PROTECTED_VERSION_1;
    
    nbytes = pwrite(fd_out, header_page, PAGE_SIZE, base);
    if (nbytes != PAGE_SIZE) {
        ret = -1;
        goto out;
    }
    
    off_t count = ebase_end - ebase_begin;
    if (count % PAGE_SIZE) {
        ret = -1;
        goto out;
    }
    
    while (count > 0) {
        nbytes = pread(fd_in, data_page, PAGE_SIZE, ebase_begin);
        if (nbytes != PAGE_SIZE) {
            ret = -1;
            goto out;
        }
        ret = [self apb_decrypt_page:data_page out:xcrypted_page];
        if (ret) {
            goto out;
        }
        nbytes = pwrite(fd_out, xcrypted_page, PAGE_SIZE, ebase_begin);
        if (nbytes != PAGE_SIZE) {
            ret = -1;
            goto out;
        }
        ebase_begin += (off_t)PAGE_SIZE;
        count -= (off_t)PAGE_SIZE;
    }
    
    ret = 1;
    
    out:
    if (fd_in >= 0) {
        close(fd_in);
    }
    if (fd_out >= 0) {
        close(fd_out);
        if (ret <= 0) {
            unlink([fOut cStringUsingEncoding:NSUTF8StringEncoding]);
        }
    }
    
    return(ret);
}

-(void)setInDirectory:(id)sender
{
    inPanel = [[NSOpenPanel alloc] init];

	/* Configure and run open panel for directories */
	[inPanel setAllowsMultipleSelection:NO];
	[inPanel setCanChooseDirectories:YES];
	[inPanel setCanChooseFiles:NO];
    [inPanel setAllowedFileTypes:nil];
    [inPanel setMessage:@"Input directory"];

    if ([inPanel runModal] == 0)
	{
        inDir = @"/";

        [ProcesPath setStringValue:inDir];

		return;
	}

    inDir = [[inPanel URL] path];

    [ProcesPath setStringValue:inDir];

    [inPanel release];
}

-(void)RecursiveHandle:(NSArray *)pt
{
	currentDirNum = 0;
    
	/* Handle directories from open panel */
	while (currentDirNum < [pt count])
	{
		/* Get directory contents */
#if MAC_OS_X_VERSION_MIN_REQUIRED < 1050
		inDirFiles = [[NSFileManager defaultManager] directoryContentsAtPath:[pt objectAtIndex:currentDirNum]];
#else /* MAC_OS_X_VERSION_MIN_REQUIRED >= 1050 */
		inDirFiles = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[pt objectAtIndex:currentDirNum] error:nil];
#endif /* MAC_OS_X_VERSION_MIN_REQUIRED < 1050 */
		
		currentFileInDirNum = 0;
		
		/* Handle files in directory */
		while (currentFileInDirNum < [inDirFiles count])
		{
			curDirFileName = [NSString stringWithFormat:@"%@/%@", [pt objectAtIndex:currentDirNum], [inDirFiles objectAtIndex:currentFileInDirNum]];
			
			/* Check if file exists and check if it is a directory */
			if ([[NSFileManager defaultManager] fileExistsAtPath:curDirFileName isDirectory:&currentDirFileIsDir])
			{
				/* Skip .DS_Store file or /Volumes directoryè */
				if ([[curDirFileName lastPathComponent] isEqualTo:@".DS_Store"])
				{
					++currentFileInDirNum;
					
					continue;
				}

                if (([curDirFileName isEqualTo:@"/Volumes"]) || ([curDirFileName isEqualTo:@"//Volumes"]))
                {
                    ++currentFileInDirNum;
					
					continue;
                }

				/* Only add files */
				if (currentDirFileIsDir == NO)
				{
                    if (secondpass == NO)
                    {
                        outFile32 = [outDir32 stringByAppendingPathComponent:[curDirFileName lastPathComponent]];

                        [self DecryptFile32:curDirFileName output:outFile32];

                        outFile64 = [outDir64 stringByAppendingPathComponent:[curDirFileName lastPathComponent]];

                        [self DecryptFile64:curDirFileName output:outFile64];
                    } else {
                        outFileUB = [outDirUB stringByAppendingPathComponent:[curDirFileName lastPathComponent]];

                        [self DecryptFile32:curDirFileName output:outFileUB];
                    }
				} else {
					currentFileInDirNumBackup[subDirCount] = currentFileInDirNum;
					currentDirNumBackup[subDirCount] = currentDirNum;
					inDirFilesBackup[subDirCount] = inDirFiles;
                        
					++subDirCount;
                    
					[self RecursiveHandle:[NSArray arrayWithObject:curDirFileName]];
                        
					--subDirCount;
                        
					currentFileInDirNum = currentFileInDirNumBackup[subDirCount];
					currentDirNum = currentDirNumBackup[subDirCount];
					inDirFiles = inDirFilesBackup[subDirCount];
				}
			}
            
			/* Increment file number */
			++currentFileInDirNum;
		}
        
		if (subDirCount > 0)
		{
			return;
		}
        
		/* Increment directory number */
		++currentDirNum;
	}
}

-(void)setOutDirs
{
    BOOL isDirPresent = NO;

    outDir32 = NSHomeDirectory();
    outDir64 = NSHomeDirectory();
    outDirUB = NSHomeDirectory();

    outDir32 = [outDir32 stringByAppendingPathComponent:@"Desktop"];
    outDir64 = [outDir64 stringByAppendingPathComponent:@"Desktop"];
    outDirUB = [outDirUB stringByAppendingPathComponent:@"Desktop"];

    outDir32 = [outDir32 stringByAppendingPathComponent:@"SysDecrypts"];
    outDir64 = [outDir64 stringByAppendingPathComponent:@"SysDecrypts"];
    outDirUB = [outDirUB stringByAppendingPathComponent:@"SysDecrypts"];

    outDir32 = [outDir32 stringByAppendingPathComponent:@"32-Bit"];
    outDir64 = [outDir64 stringByAppendingPathComponent:@"64-Bit"];
    outDirUB = [outDirUB stringByAppendingPathComponent:@"Universal"];

    if (![[NSFileManager defaultManager] fileExistsAtPath:outDir32 isDirectory:&isDirPresent])
    {
        [[NSFileManager defaultManager] createDirectoryAtPath:outDir32 withIntermediateDirectories:YES attributes:nil error:nil];
    }

    if (![[NSFileManager defaultManager] fileExistsAtPath:outDir64 isDirectory:&isDirPresent])
    {
        [[NSFileManager defaultManager] createDirectoryAtPath:outDir64 withIntermediateDirectories:YES attributes:nil error:nil];
    }

    if (![[NSFileManager defaultManager] fileExistsAtPath:outDirUB isDirectory:&isDirPresent])
    {
        [[NSFileManager defaultManager] createDirectoryAtPath:outDirUB withIntermediateDirectories:YES attributes:nil error:nil];
    }
}

-(void)decryptDone:(id)sender
{
    [lock unlock];
    [[NSNotificationCenter defaultCenter] removeObserver:workthread];
}

-(void)runDecryptThread:(id)arg
{
    busy = YES;

    inDir = [ProcesPath stringValue];

    [InProgress setIndeterminate:YES];
    [InProgress startAnimation:self];
    
    [self setOutDirs];
    
    subDirCount = 0;

    secondpass = NO;

    [self RecursiveHandle:[NSArray arrayWithObject:inDir]];

    secondpass = YES;

    [self RecursiveHandle:[NSArray arrayWithObject:outDir64]];

    secondpass = NO;

    [InProgress stopAnimation:self];

    busy = NO;
}

-(void)runDecrypt:(id)sender
{
    lock = [[[NSLock alloc] init] autorelease];
    alert = [[[NSAlert alloc] init] autorelease];
    workthread = [[[NSThread alloc] initWithTarget:self selector:@selector(runDecryptThread:) object:busy] autorelease];

    [[NSNotificationCenter defaultCenter] addObserver:workthread selector:@selector(decryptDone:) name:NSThreadWillExitNotification object:self];

    if (busy == YES)
    {
        [alert setMessageText:@"Do you want to cancel the decryption scan?"];
        [alert setInformativeText:@"Decryption is running!"];
        [alert setIcon:[[NSApplication sharedApplication] applicationIconImage]];
        [alert addButtonWithTitle:@"YES"];
        [alert addButtonWithTitle:@"NO"];

        if ([alert runModal] == NSAlertFirstButtonReturn)
        {
            [workthread cancel];
        }

        return;
    }
    
    if ([oldBinaries state] > 0)
    {
        decryptOld = YES;
    } else {
        decryptOld = NO;
    }

    if ([lock tryLock] == YES)
    {
        [workthread start];
    }
}
@end
