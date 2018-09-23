using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NfcDotNet.LibNfc
{
    public static class Nfc
    {
        public const int DeviceNameLength = 256;
        public const int DevicePortLength = 64;
        public const int MaxUserDefinedDevices = 4;
        public const int NfcBufferSizeConnectString = 1024;

        /* Library initialization/deinitialization */
        [DllImport("libnfc", EntryPoint = "nfc_init", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Init(out IntPtr context);

        [DllImport("libnfc", EntryPoint = "nfc_exit", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Exit(IntPtr context);

        /* NFC Device/Hardware manipulation */
        [DllImport("libnfc", EntryPoint = "nfc_open", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Open(IntPtr context, string nfcConnstring);

        [DllImport("libnfc", EntryPoint = "nfc_close", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Close(IntPtr pnd);

        [DllImport("libnfc", EntryPoint = "nfc_list_devices", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ListDevices(IntPtr context, IntPtr connstrings, uint connstrings_len);

        [DllImport("libnfc", EntryPoint = "nfc_initiator_init", CallingConvention = CallingConvention.Cdecl)]
        public static extern int InitiatorInit(IntPtr pnd);

        [DllImport("libnfc", EntryPoint = "nfc_perror", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void Perror(IntPtr pnd, string s);

        [DllImport("libnfc", EntryPoint = "nfc_device_get_name", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr _DeviceGetName(IntPtr pnd);

        public static string DeviceGetName(IntPtr pnd) => Marshal.PtrToStringAnsi(_DeviceGetName(pnd));

        [DllImport("libnfc", EntryPoint = "nfc_device_set_property_bool", CallingConvention = CallingConvention.Cdecl)]
        public static extern int DeviceSetPropertyBool(IntPtr pnd, NfcProperty property, bool bEnable);
        
        [DllImport("libnfc", EntryPoint = "nfc_initiator_transceive_bytes", CallingConvention = CallingConvention.Cdecl)]
        public static extern int InitiatorTransceiveBytes(IntPtr pnd, byte[] pbtTx, uint szTx, byte[] pbtRx, uint szRx, int timeout);
        
        [DllImport("libnfc", EntryPoint = "nfc_initiator_transceive_bits", CallingConvention = CallingConvention.Cdecl)]
        public static extern int InitiatorTransceiveBits(IntPtr pnd, byte[] pbtTx, uint szTxBits, byte[] pbtTxPar, byte[] pbtRx, uint szRx, byte[] pbtRxPar);
        
        [DllImport("libnfc", EntryPoint = "nfc_initiator_transceive_bytes_timed", CallingConvention = CallingConvention.Cdecl)]
        public static extern int InitiatorTransceiveBytesTimed(IntPtr pnd, byte[] pbtTx, uint szTx, byte[] pbtRx, uint szRx, ref uint cycles);
        
        [DllImport("libnfc", EntryPoint = "nfc_initiator_transceive_bits_timed", CallingConvention = CallingConvention.Cdecl)]
        public static extern int InitiatorTransceiveBitsTimed(IntPtr pnd, byte[] pbtTx, uint szTxBits, byte[] pbtTxPar, byte[] pbtRx, uint szRx, byte[] pbtRxPar, ref uint cycles);

        [DllImport("libnfc", EntryPoint = "iso14443a_crc_append", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Iso14443aCrcAppend(byte[] pbtData, uint szLen);
        
        [DllImport("libnfc", EntryPoint = "nfc_version", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr _Version();

        public static string Version() => Marshal.PtrToStringAnsi(_Version());


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct Context
        {
            [MarshalAs(UnmanagedType.U1)]
            public bool AllowAutoscan;

            [MarshalAs(UnmanagedType.U1)]
            public bool AllowIntrusiveScan;

            public uint LogLevel;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UserDefinedDevice[] userDefinedDevice;

            public uint UserDefinedDeviceCount;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct UserDefinedDevice
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Name;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
            public string ConnString;

            [MarshalAs(UnmanagedType.U1)]
            bool Optional;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class Device
        {
        }
    }
}
