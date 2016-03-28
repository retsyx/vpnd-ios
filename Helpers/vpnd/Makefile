CC=clang
CFLAGS=-I../../include -I../../Family -I../../Controller -framework Foundation -framework SystemConfiguration --target=armv7a-apple-darwin10 -arch arm64 -miphoneos-version-min=7.0 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

vpnd: main.c cf_utils.c pppoptions.c sys_MacOSX.c vpnoptions.c vpnplugins.c
	$(CC) -o vpnd main.c cf_utils.c pppoptions.c sys_MacOSX.c vpnoptions.c vpnplugins.c $(CFLAGS)
