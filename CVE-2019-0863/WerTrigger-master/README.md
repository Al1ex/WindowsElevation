# WerTrigger
Weaponizing for privileged file writes bugs with windows problem reporting

#### Short Description:
I've found phoneinfo.dll (which is missing in system32 dir) has been loaded by wermgr.exe (windows problem reporting) when I enable boot logging in Procmon. It mean, `phoneinfo.dll` is loaded after reboot. Then, I asked to [@jonasLyk](https://twitter.com/jonasLyk) that can I trigger to load `phoneinfo.dll` without reboot and he said "yes!". And then, This trigger was happened.  

#### *Note:*
*you can also use [@it4man](https://twitter.com/itm4n)'s  [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) as a weapon for privileged file writes bugs and also there's another techniques at here [FileWrite2system](https://github.com/sailay1996/awesome_windows_logical_bugs/blob/master/FileWrite2system.txt)*

#### For testing purposes:
1. **As an administrator**, copy `phoneinfo.dll` to `C:\Windows\System32\`
2. Place `Report.wer` file and `WerTrigger.exe` in a same directory.
3. Then, run `WerTrigger.exe`.
4. Enjoy a shell as NT AUTHORITY\SYSTEM.

![test1](https://github.com/sailay1996/WerTrigger/blob/master/werTrigger.jpg)

*by [@404death](https://twitter.com/404death)*

*Thanks to: [@jonasLyk](https://twitter.com/jonasLyk) for giving advice which is `without reboot technique`*
