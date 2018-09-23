using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NfcDotNet.LibNfc
{
    public class NfcDevice: IDisposable
    {
        private IntPtr devicePointer;
        private bool disposed = false;

        string _name;

        public string Name
        {
            get
            {
                if (_name == null)
                    _name = Nfc.DeviceGetName(devicePointer);
                return _name;
            }
        }

        public NfcDevice(IntPtr devicePointer)
        {
            this.devicePointer = devicePointer;
        }

        public int InitiatorInit() =>
            Nfc.InitiatorInit(devicePointer);

        public int DeviceSetPropertyBool(NfcProperty property, bool enable) =>
            Nfc.DeviceSetPropertyBool(devicePointer, property, enable);

        public int InitiatorTransceiveBitsTimed(byte[] pbtTx, uint szTxBits, byte[] pbtTxPar, byte[] pbtRx, uint szRx, byte[] pbtRxPar, ref uint cycles) =>
            Nfc.InitiatorTransceiveBitsTimed(devicePointer, pbtTx, szTxBits, pbtTxPar, pbtRx, szRx, pbtRxPar, ref cycles);

        public int InitiatorTransceiveBits(byte[] pbtTx, uint szTxBits, byte[] pbtTxPar, byte[] pbtRx, uint szRx, byte[] pbtRxPar) =>
            Nfc.InitiatorTransceiveBits(devicePointer, pbtTx, szTxBits, pbtTxPar, pbtRx, szRx, pbtRxPar);

        public int InitiatorTransceiveBytesTimed(byte[] pbtTx, uint szTx, byte[] pbtRx, uint szRx, ref uint cycles) =>
            Nfc.InitiatorTransceiveBytesTimed(devicePointer, pbtTx, szTx, pbtRx, szRx, ref cycles);

        public int InitiatorTransceiveBytes(byte[] pbtTx, uint szTx, byte[] pbtRx, uint szRx, int timeout) =>
            Nfc.InitiatorTransceiveBytes(devicePointer, pbtTx, szTx, pbtRx, szRx, timeout);

        public void Perror(string s) =>
            Nfc.Perror(devicePointer, s);

        public void Close() => Dispose();

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
                Nfc.Close(devicePointer);
                devicePointer = IntPtr.Zero;
                disposed = true;
            }
        }

        ~NfcDevice()
        {
            Dispose(false);
        }
    }
}
