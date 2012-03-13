// http://stackoverflow.com/questions/5247912/saving-email-password-to-keychain-in-ios

#import "SimpleKeychain.h"
#import "SFCrypto.h"

@implementation SimpleKeychain

+ (NSMutableDictionary *)getKeychainQuery:(NSString *)service {
    return [NSMutableDictionary dictionaryWithObjectsAndKeys:
            (id)kSecClassGenericPassword, (id)kSecClass,
            service, (id)kSecAttrService,
            service, (id)kSecAttrAccount,
            //(id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly, (id)kSecAttrAccessible,
            (id)kSecAttrAccessibleAfterFirstUnlock, (id)kSecAttrAccessible,
            nil];
}

+ (void)save:(NSString *)service data:(id)data {
    if( !data ) return;
        
    NSMutableDictionary *keychainQuery = [self getKeychainQuery:service];
    SecItemDelete((CFDictionaryRef)keychainQuery);  
    
    [keychainQuery setObject:[NSKeyedArchiver archivedDataWithRootObject:
                              (  [data isKindOfClass:[NSString class]] 
                                 ? [SFCrypto crypt:[data dataUsingEncoding:NSUTF8StringEncoding]
                                         operation:kCryptEncrypt]
                                 : data )]
                      forKey:(id)kSecValueData];
    
    SecItemAdd((CFDictionaryRef)keychainQuery, NULL);
}

+ (id)load:(NSString *)service {
    id ret = nil;
    NSMutableDictionary *keychainQuery = [self getKeychainQuery:service];
    [keychainQuery setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    [keychainQuery setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    CFDataRef keyData = NULL;
    if (SecItemCopyMatching((CFDictionaryRef)keychainQuery, (CFTypeRef *)&keyData) == noErr) {
        @try {
            ret = [NSKeyedUnarchiver unarchiveObjectWithData:(NSData *)keyData];
        }
        @catch (NSException *e) {
            NSLog(@"Unarchive of %@ failed: %@", service, e);
        }
        @finally {}
    }
    if (keyData) CFRelease(keyData);
    
    if( [ret isKindOfClass:[NSData class]] )
        return [[[NSString alloc] initWithData:[SFCrypto crypt:ret
                                                     operation:kCryptDecrypt]
                                      encoding:NSUTF8StringEncoding] autorelease];
    
    return ret;
}

+ (void)delete:(NSString *)service {
    NSMutableDictionary *keychainQuery = [self getKeychainQuery:service];
    SecItemDelete((CFDictionaryRef)keychainQuery);
}

@end