CC=clang
CFLAGS=-I./include -I../../Family -I../../Controller -framework Foundation -framework SystemConfiguration -framework CoreFoundation -framework CoreTelephony --target=armv7a-apple-darwin10 -arch arm64 -miphoneos-version-min=7.0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk 

DSAuth: main.c DSUser.c
	$(CC) -o DSAuth main.c DSUser.c $(CFLAGS)
