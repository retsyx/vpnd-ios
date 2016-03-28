CC=clang
CFLAGS=-bundle -bundle_loader ../../../Helpers/vpnd/vpnd -I../../../include -I../../Family -I../../Controller -framework Foundation -framework CoreFoundation --target=armv7a-apple-darwin10 -arch arm64 -miphoneos-version-min=7.0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

PPTP: main.c 
	$(CC) -o PPTP main.c $(CFLAGS)
