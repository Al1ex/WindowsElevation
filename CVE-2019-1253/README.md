# CVE-2019-1253
## AppXSvc Arbitrary File Security Descriptor Overwrite EoP

I have independently reported this vulnerability to MSRC, however, my submission turned out to be a duplicate due to the fact that the fix for [CVE-2019-1253](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1253) also addressed this issue. My PoC differs from the ones created by [Chris Danieli](https://github.com/padovah4ck/CVE-2019-1253) or [Nabeel Ahmed](https://github.com/rogue-kdc/CVE-2019-1253) because this exploit gives 'Full Control' over the target file. My research was inspired by [CVE-2019-0841](https://github.com/rogue-kdc/CVE-2019-0841) originally reported by [Nabeel Ahmed](https://twitter.com/rogue_kdc).

![Video PoC](https://github.com/sgabe/CVE-2019-1253/blob/master/AppXSvcEoP.gif)
