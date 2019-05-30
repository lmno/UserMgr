# NSIS UserMgr plugin
NSIS plugin to create and manage users and groups on Windows. 

This is a fork of the original plugin available on the NSIS site. Original plugin and documentation can be found here https://nsis.sourceforge.io/UserMgr_plug-in

## Origin
This plugin was originally created by [Heiko Gerstung](https://nsis.sourceforge.io/User:Hgerstung).

This code is based on the modifications made by [JasonFriday13 ](http://forums.winamp.com/member.php?u=173435) and posted to the [WinAmp forum](http://forums.winamp.com/showpost.php?p=3001678&postcount=51) which adds Unicode support.

I made this fork because I wanted to fix the a bug in `UserMgr::CreateAccount`. The login script path of newly created users where uninitialized, filling it with random garbage which produced an error when you open the user property editor. I have upgraded the project and compiled it with Visual Studio 2019.

## License
The original code contain no license and I do not claim any ownership of this code.

> Note: This code is old and made for older versions of Windows and I have made no attempt to ensure or verify that this plugin is fully compatible on Windows 10 or any other Windows versions. Though I use some of these commands on Windows 10 myself, I make no guarantee. Use this at your own risk.