using System;

namespace tRWXi.Data
{
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
}
