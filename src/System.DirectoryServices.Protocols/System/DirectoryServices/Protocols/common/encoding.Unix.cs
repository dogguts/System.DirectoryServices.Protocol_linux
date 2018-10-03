using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    internal class Encoding
    {
        internal static Func<IntPtr, string> PtrToString = PtrToStringUTF8;
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

        private static string PtrToStringUtf8(IntPtr ptr, int length)
        {
            if (ptr == IntPtr.Zero)
                return null;

            byte[] buff = new byte[length];
            Marshal.Copy(ptr, buff, 0, length);
            return System.Text.UTF8Encoding.UTF8.GetString(buff);
        }

        public static string PtrToStringUTF8(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }

            int len = 0;

            while (Marshal.ReadByte(ptr, len) != 0)
            {
                ++len;
            }

            if (len == 0)
            {
                return string.Empty;
            }

            byte[] buffer = new byte[len];
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
            return System.Text.Encoding.UTF8.GetString(buffer);
        }



    }
}