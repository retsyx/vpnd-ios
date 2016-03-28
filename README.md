# vpnd-ios

Apple’s vpnd lightly modified for operation on jailbroken iOS.

The only supported VPN type is PPTP. IPSec is commented out and L2TP is not configured or known to work.

Getting this to work requires some familiarity and comfort with the Unix command line and editing a couple configuration files.

## Prerequisites

1. Jailbroken iPhone, iPad or equivalent running iOS 9.0 or later (may work on earlier versions too).
1. Mac with Xcode, version 7.0 or later.

## Building

1. Open Terminal.
1. Navigate to vpnd-ios/Helpers/vpnd/.
1. Run make. This creates the ‘vpnd’ binary.
1. Navigate to vpnd-ios/Drivers/PPTP/PPTP-vpn/.
1. Run make. This creates the ‘PPTP’ binary. Note the ‘PPTP-vpn-Info.plist’ file alongside it.

## Installing

1. As root, copy these files to your jailbroken iDevice at the specified locations. Create directories as necessary:
  * vpnd-ios/Helpers/vpnd/vpnd -> /usr/sbin/vpnd
  * vpnd-ios/Drivers/PPTP/PPTP-vpn/PPTP -> /System/Library/Extensions/PPTP.ppp/PlugIns/PPTP.vpn/PPTP
  * vpnd-ios/Drivers/PPTP/PPTP-vpn/PPTP-vpn-Info.plist -> /System/Library/Extensions/PPTP.ppp/PlugIns/PPTP.vpn/PPTP-vpn-Info.plist
  * vpnd-ios/extras/com.apple.RemoteAccessServers.plist -> /var/preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist
  * vpnd-ios/extras/chap-secrets -> /etc/ppp/chap-secrets
  * vpnd-ios/extras/com.apple.vpnd-ios.plist -> /Library/LaunchDaemons/com.apple.vpnd-ios.plist
1. Edit /var/preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist as per your requirements. ‘man 5 vpnd’ in OS X Terminal may be helpful for this.
1. Edit /etc/ppp/chap-secrets as per your requirements. This is a standard pppd chap-secrets file.
1. On the iDevice run:
  * ldid -S /usr/bin/vpnd
  * ldid -S /System/Library/Extensions/PPTP.ppp/PlugIns/PPTP.vpn/PPTP
  * launchctl load /Library/LaunchDaemons/com.apple.vpnd-ios.plist

At this point, vpnd should be running on your iDevice and you should be able to connect VPN clients to it.

If for some reason you don’t see that vpnd is running you can try to run it manually, e.g. ‘/usr/sbin/vpnd’


