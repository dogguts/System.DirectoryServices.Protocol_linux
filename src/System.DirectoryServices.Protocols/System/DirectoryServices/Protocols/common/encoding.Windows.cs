using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    internal class Encoding
    {
        internal static Func<IntPtr, string> PtrToString = Marshal.PtrToStringUni;
        internal static Func<string, IntPtr> StringToHGlobal = Marshal.StringToHGlobalUni;
    }
}
