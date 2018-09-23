using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NfcDotNet.LibNfc
{
    public class NfcContext : IDisposable
    {
        protected IntPtr contextPointer;
        private bool disposed = false;

        public NfcContext()
        {
            Nfc.Init(out contextPointer);
            if (contextPointer == IntPtr.Zero)
                throw new Exception("Unable to init libnfc (malloc)");
        }

        public List<string> ListDeviceNames()
        {
            int someUnknownCount = 8;
            IntPtr connectionStringsPointer = Marshal.AllocHGlobal(Nfc.NfcBufferSizeConnectString * someUnknownCount);
            var devicesCount = Nfc.ListDevices(contextPointer, connectionStringsPointer, (uint)someUnknownCount);

            var devices = new List<string>();
            for (int i = 0; i < devicesCount; i++)
                devices.Add(Marshal.PtrToStringAnsi(connectionStringsPointer + i * Nfc.NfcBufferSizeConnectString));

            Marshal.FreeHGlobal(connectionStringsPointer);
            return devices;
        }

        public virtual NfcDevice OpenDevice(string name = null)
        {
            IntPtr devicePointer;
            try
            {
                devicePointer = Nfc.Open(contextPointer, name);
                if (devicePointer == IntPtr.Zero)
                    throw new Exception();
            }
            catch (Exception)
            {
                throw new Exception("Error opening NFC reader");
            }

            return new NfcDevice(devicePointer);
        }

        public string Version() => Nfc.Version();

        public void Exit() => Dispose();

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources.
                    // component.Dispose();
                }
                Nfc.Exit(contextPointer);
                contextPointer = IntPtr.Zero;
                disposed = true;
            }
        }

        ~NfcContext()
        {
            Dispose(false);
        }
    }
}
