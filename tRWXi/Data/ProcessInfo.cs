using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static tRWXi.Utils.Win32;

namespace tRWXi.Data
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
}
