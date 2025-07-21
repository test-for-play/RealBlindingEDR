# RealBlindingEDR (C# Version)

This is a C# port of the original [RealBlindingEDR](https://github.com/test-for-play/RealBlindingEDR) project.

## Introduction

This project implements the clearing of the following kernel callbacks:

1. Delete the callback registered by `CmRegisterCallback(Ex)`
2. Delete the callback registered by `MiniFilter driver`
3. Delete the callbacks registered by `ObRegisterCallbacks()`
4. Delete the callback registered by `PsSetCreateProcessNotifyRoutine(Ex)`
5. Delete the callback registered by `PsSetCreateThreadNotifyRoutine(Ex)`
6. Delete the callback registered by `PsSetLoadImageNotifyRoutine(Ex)`

**After deleting the kernel callback, the following 3 effects can finally be achieved:**

1. **Blinding AV/EDR**
    
    While keeping the AV/EDR process running normally, it makes it impossible to monitor any process/thread activity, any file landing, registry deletion, high-privilege handle acquisition and many other sensitive behaviors.
    
2. **Permanently turn off or disable AV/EDR**
    
    Since the registry and minifilter kernel notification callbacks are deleted, AV/EDR can be permanently turned off (even if the system is restarted) by modifying the registry or directly deleting the AV/EDR file.
    
3. **Kill AV/EDR process**
    
    Since the object handle notification callback has been removed, it is now possible to terminate the AV/EDR process with normal administrator user rights.

## Disclaimer

This project is not targeted at any AV/EDR manufacturers. The code examples are only for research and learning, and are not allowed to be used maliciously. If there is any malicious use, it has nothing to do with me.

## Usage

1. Download the project code, open the `Program.cs` file, and configure the absolute path where the available driver is located.
		
    This project supports two driver applications: [dbutil_2_3.sys](https://www.loldrivers.io/drivers/a4eabc75-edf6-4b74-9a24-6a26187adabf/) 、[echo_driver.sys](https://www.loldrivers.io/drivers/afb8bb46-1d13-407d-9866-1daa7c82ca63/)
		
    `private const int DriverType = 1` means using echo_driver.sys
   
    `private const int DriverType = 2` means using dbutil_2_3.sys
   
    `private const string DrivePath = @"C:\ProgramData\echo_driver.sys"` is used to specify the path where the driver is located
     
    The dbutil_2_3.sys driver supports win7 and above.
    
    The echo_driver.sys driver supports win10 and above.
    
    **Note:** Currently, these two drivers cannot be loaded on the latest version of Win11 [10.0.22621.2506] (certificate revoked, error: c0000603)
    
2. Compile the project and run it as administrator on the computer with AV/EDR installed.
3. After execution, you will see the following effect: (listing the names of all drivers that registered these callbacks)
    
4. It's not over yet. You need to open the `Program.cs` file again, find out the driver name of AV/EDR in the output result of step 3 (you can judge it through Google or search local files), and add it to `private static readonly string[] AVDriver = { null };` in the array.

    **Note:** Be sure not to add the normal driver name of the Windows system to this array, otherwise it may cause the system to crash.
5. Compile again and run it directly to automatically clear all the above callbacks of the specified driver (the name of the driver with deleted callbacks will be followed by a [Clear] flag).
6. If you run it again, you will find that there are no AV/EDR names in these output callbacks.

## Requirements

- .NET 6.0 or higher
- Windows 7/10/11 or Windows Server 2008R2/2012R2/2016/2019/2022 (64-bit)
- Administrator privileges

## Building

```
dotnet build -c Release
```

## Running

```
dotnet run -c Release
```

Or run the compiled executable directly with administrator privileges.

## Acknowledgments

This project is a C# port of the original [RealBlindingEDR](https://github.com/test-for-play/RealBlindingEDR) project.

Thanks to the following articles and projects for helping with the original implementation:

1. [OBREGISTERCALLBACKS AND COUNTERMEASURES](https://douggemhax.wordpress.com/2015/05/27/obregistercallbacks-and-countermeasures/)
2. [Windows Anti-Debug techniques - OpenProcess filtering](https://blog.xpnsec.com/anti-debug-openprocess/)
3. [Mimidrv In Depth: Exploring Mimikatz's Kernel Driver](https://medium.com/@matterpreter/mimidrv-in-depth-4d273d19e148)
4. [Part 1: Fs Minifilter Hooking](https://aviadshamriz.medium.com/part-1-fs-minifilter-hooking-7e743b042a9d)
5. [EchoDrv](https://github.com/YOLOP0wn/EchoDrv)
6. [Windows Kernel Ps Callbacks Experiments](http://blog.deniable.org/posts/windows-callbacks/)
7. [Silencing the EDR. How to disable process, threads and image-loading detection callbacks](https://www.matteomalvica.com/blog/2020/07/15/silencing-the-edr/)
8. [Removing-Kernel-Callbacks-Using-Signed-Drivers](https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/)
9. [EchOh-No! a Vulnerability and PoC demonstration in a popular Minecraft AntiCheat tool](https://ioctl.fail/echo-ac-writeup/)