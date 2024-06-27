using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace lab4
{
    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        const uint TOKEN_QUERY = 0x0008;

        static void Main(string[] args)
        {
            List<ProcessInfo> processList = new List<ProcessInfo>();

            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string processPath = GetProcessPath(process);
                    bool isSigned = IsProcessSigned(processPath);

                    processList.Add(new ProcessInfo
                    {
                        ProcessId = process.Id,
                        ProcessPath = processPath,
                        IsSigned = isSigned
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing process {process.Id}: {ex.Message}");
                }
            }

            string jsonOutput = JsonSerializer.Serialize(processList, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText("processes.json", jsonOutput);

            Console.WriteLine("Process information has been saved to processes.json");
        }

        static string GetProcessPath(Process process)
        {
            StringBuilder processPath = new StringBuilder(1024);
            IntPtr handle = IntPtr.Zero;

            try
            {
                handle = process.Handle;

                uint size = (uint)processPath.Capacity;
                if (QueryFullProcessImageName(handle, 0, processPath, ref size))
                {
                    return processPath.ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving process path for process {process.Id}: {ex.Message}");
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    CloseHandle(handle);
                }
            }

            throw new Exception("Unable to retrieve process path.");
        }

        static bool IsProcessSigned(string processPath)
        {
            try
            {
                X509Certificate cert = X509Certificate.CreateFromSignedFile(processPath);
                X509Certificate2 cert2 = new X509Certificate2(cert);

                // Check if the certificate is valid and trusted
                return cert2.Verify();
            }
            catch
            {
                return false;
            }
        }

        class ProcessInfo
        {
            public int ProcessId { get; set; }
            public string ProcessPath { get; set; }
            public bool IsSigned { get; set; }
        }
    }
}
