using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    internal class Encoding
    {
        internal static Func<IntPtr, string> PtrToString = Marshal.PtrToStringUTF8;
        internal static Func<string, IntPtr> StringToHGlobal = StringToHGlobalUTF8;

        private static IntPtr StringToHGlobalUTF8(string s, out int length)
        {
            if (s == null)
            {
                length = 0;
                return IntPtr.Zero;
            }

            var bytes = System.Text.Encoding.UTF8.GetBytes(s);
            var ptr = Marshal.AllocHGlobal(bytes.Length + 1);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            Marshal.WriteByte(ptr, bytes.Length, 0);
            length = bytes.Length;

            return ptr;
        }

        private static IntPtr StringToHGlobalUTF8(string s)
        {
            int temp;
            return StringToHGlobalUTF8(s, out temp);
        }
    }
}