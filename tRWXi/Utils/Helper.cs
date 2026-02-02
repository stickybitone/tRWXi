using System;

namespace tRWXi.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("tRWXi v1.4.0\n\nUsage: \n\t.\\tRWXi.exe /enumerate ;" +
                                     "\n\t.\\tRWXi.exe /inject  /pid=<pid> /address=<hex address> /url=<remote shell code> [/execute] ;" +
                                     "\n\t.\\tRWXi.exe /inject  /pid=<pid> /address=<hex address> /data=<hex code> [/execute] ;" +
                                     "\n\t.\\tRWXi.exe /read    /pid=<pid> /address=<hex address> /size=<size> ;" +
                                     "\n\t.\\tRWXi.exe /trigger /pid=<pid> /address=<hex address> ;");
        }
    }
}
