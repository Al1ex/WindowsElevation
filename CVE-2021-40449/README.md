# CallbackHell

Exploit for CVE-2021-40449 (Win32k - LPE)

- [CallbackHell](#callbackhell)
  - [Description](#description)
  - [Technical Writeup](#technical-writeup)
  - [PoC](#poc)
  - [References](#references)

## Description

CVE-2021-40449 is a use-after-free in Win32k that allows for local privilege escalation.

The vulnerability was found in the wild by [Kaspersky](https://www.kaspersky.com/blog/mysterysnail-cve-2021-40449/42448/).

The discovered exploit was written to support the following Windows products:
 - Microsoft Windows Vista
 - Microsoft Windows 7
 - Microsoft Windows 8
 - Microsoft Windows 8.1
 - Microsoft Windows Server 2008
 - Microsoft Windows Server 2008 R2
 - Microsoft Windows Server 2012
 - Microsoft Windows Server 2012 R2
 - Microsoft Windows 10 (build 14393)
 - Microsoft Windows Server 2016 (build 14393)
 - Microsoft Windows 10 (build 17763)
 - Microsoft Windows Server 2019 (build 17763)

However, this exploit is current only tested on the following versions:
 - Microsoft Windows 10 (build 14393)
 - Microsoft Windows 10 (build 17763)

## Technical Writeup

I highly recommend reading Kaspersky's [technical writeup](https://securelist.com/mysterysnail-attacks-with-windows-zero-day/104509/) before proceeding.

As mentioned in the technical writeup by Kasperky, the vulnerability exists in `GreResetDCInternal`. If an attacker hooks the user-mode callback `DrvEnablePDEV`, which is called during `hdcOpenDCW`, it is possible to destroy the original device context by calling `ResetDC`, which causes a use-after-free in the kernel when the user-mode callback returns.

The following pseudo-code is made partially from the leaked Windows XP source code and by reverse-engineering the latest (before the patch) `GreResetDCInternal` from `Win32kfull.sys`. The irrelevant parts have been removed with `[...]`. Look for the `VULN: ` comments.
```c
BOOL GreResetDCInternal(
    HDC hdc,
    DEVMODEW *pdmw,
    BOOL *pbBanding,
    DRIVER_INFO_2W *pDriverInfo2,
    PVOID ppUMdhpdev)
{
    // [...]
    HDC hdcNew;

    {
        // Create DCOBJ from HDC
        DCOBJ dco(hdc);

        if (!dco.bValid())
        {
            SAVE_ERROR_CODE(ERROR_INVALID_HANDLE);
        }
        else
        {
            // Create DEVOBJ from `dco`
            PDEVOBJ po(dco.hdev());

            // [...]

            // Create the new DC
            // VULN: Can result in a usermode callback that destroys old DC, which
            // invalidates `dco` and `po`
            hdcNew = hdcOpenDCW(L"",
                                pdmw,
                                DCTYPE_DIRECT,
                                po.hSpooler,
                                prton,
                                pDriverInfo2,
                                ppUMdhpdev);

            if (hdcNew)
            {
                po->hSpooler = NULL;

                DCOBJ dcoNew(hdcNew);

                if (!dcoNew.bValid())
                {
                    SAVE_ERROR_CODE(ERROR_INVALID_HANDLE);
                }
                else
                {
                    // Transfer any remote fonts

                    dcoNew->pPFFList = dco->pPFFList;
                    dco->pPFFList = NULL;

                    // Transfer any color transform

                    dcoNew->pCXFList = dco->pCXFList;
                    dco->pCXFList = NULL;

                    PDEVOBJ poNew((HDEV)dcoNew.pdc->ppdev());

                    // Let the driver know
                    // VULN: Method is taken from old (possibly destroyed) `po`
                    PFN_DrvResetPDEV rfn = po->ppfn[INDEX_DrvResetPDEV];

                    if (rfn != NULL)
                    {
                        (*rfn)(po->dhpdev, poNew->dhpdev);
                    }

                    // [...]
                }
            }
        }
    }

    // Destroy old DC
    // [...]
}
```

As can be seen from the pseudo-code, the old device context can be freed in a user-mode callback from the `hdcOpenDCW` call, and later on, the method `DrvResetPDEV` is retrieved from the old device context and called with `(po->dhpdev, poNew->dhpdev)`.

To create and hook a device context, one can do the following:

- Find an available printer with `EnumPrinters`
- Load the printer driver into memory with `OpenPrinter`, `GetPrinterDriver` and `LoadLibraryExA`
- Get the printer driver's user-mode callback table with `GetProcAddress` and `DrvEnableDriver`
- Unprotect the printer driver's user-mode callback table with `VirtualProtect`
- Overwrite the printer driver's desired user-mode callback table entries
- Create a device context for the printer with `CreateDC(NULL, printerName, NULL, NULL)`

We should now have a device context for a printer with hooked user-mode callbacks.

We're interested in only one hook, namely `DrvEnablePDEV`. This hook is interesting in two aspects: triggering the UAF and controlling the arguments, as described earlier. To trigger the UAF vulnerability, we will call `ResetDC` inside of the hook, which will destroy the old device context. When we return from the hook, we will still be inside the first `GreResetDCInternal`, which will shortly after get and call the function pointer for `DrvResetPDEV` from our old and destroyed device context with the two arguments that got returned from `DrvEnablePDEV`; the old and the new `DHPDEV`.

If your process is running with a medium integrity level, KASLR should not be an issue with the help of `EnumDeviceDrivers` and `NtQuerySystemInformation`. 

Kaspersky mentions that the original exploit used GDI palette objects and a single kernel function call to achieve arbitrary memory read/write. This exploit uses [a technique to allocate a BitMapHeader on the big pool](https://blahcat.github.io/2019/03/17/small-dumps-in-the-big-pool/) and `RtlSetAllBits` to enable all privileges on our current process token. The `BitMapHeader` will point to our current process token's `_SEP_TOKEN_PRIVILEGES`. By calling `RtlSetAllBits(BitMapHeader)`, it's possible to enable all privileges for our current process token with a single kernel function call. From here, one can abuse the new privileges to get SYSTEM. This exploit uses `SeDebugPrivilege` to inject shellcode into the `winlogon.exe` process.

## PoC

![./poc.png](https://raw.githubusercontent.com/ly4k/CallbackHell/main/poc.png)

## References

- [https://securelist.com/mysterysnail-attacks-with-windows-zero-day/104509/](https://securelist.com/mysterysnail-attacks-with-windows-zero-day/104509/)
- [https://github.com/siberas/CVE-2016-3309_Reloaded/](https://github.com/siberas/CVE-2016-3309_Reloaded/)
- [https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation)
- [https://github.com/KaLendsi/CVE-2021-40449-Exploit](https://github.com/KaLendsi/CVE-2021-40449-Exploit)
- [https://mp.weixin.qq.com/s/AcFS0Yn9SDuYxFnzbBqhkQ](https://mp.weixin.qq.com/s/AcFS0Yn9SDuYxFnzbBqhkQ)
