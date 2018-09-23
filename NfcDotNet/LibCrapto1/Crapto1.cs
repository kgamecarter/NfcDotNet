﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NfcDotNet.LibCrapto1
{
    public class Crapto1: IDisposable
    {
        private IntPtr crypto1StatePtr;
        private bool disposed = false;

        public Crypto1State State
        {
            get
            {
                return Marshal.PtrToStructure<Crypto1State>(crypto1StatePtr);
            }
            set
            {
                Marshal.StructureToPtr(value, crypto1StatePtr, false);
            }
        }

        public Crapto1(ulong key)
        {
            crypto1StatePtr = Crapto1Func.Crypto1Create(key);
        }

        public byte Crypto1Bit(byte v = 0, bool isEncrypted = false) =>
            Crapto1Func.Crypto1Bit(crypto1StatePtr, v, isEncrypted ? 1 : 0);

        public byte Crypto1Byte(byte v = 0, bool isEncrypted = false) =>
            Crapto1Func.Crypto1Byte(crypto1StatePtr, v, isEncrypted ? 1 : 0);

        public uint Crypto1Word(uint v = 0, bool isEncrypted = false) =>
            Crapto1Func.Crypto1Word(crypto1StatePtr, v, isEncrypted ? 1 : 0);

        public byte PeekCrypto1Bit() =>
            Crapto1Func.Filter(State.Odd);

        public void Encrypt(byte[] data, byte[] parirty, int offset, int length, bool addin = false)
        {
            int end = offset + length;
            for (int i = offset; i < end; i++)
            {
                // 計算 Parity
                parirty[i] = Parity.OddParity8(data[i]);
                // 加密
                data[i] ^= Crypto1Byte(addin ? data[i] : (byte)0);
                // 加密 Parity
                parirty[i] ^= PeekCrypto1Bit();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            // This object will be cleaned up by the Dispose method.
            // Therefore, you should call GC.SupressFinalize to
            // take this object off the finalization queue
            // and prevent finalization code for this object
            // from executing a second time.
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // Dispose managed resources.
                }
                Crapto1Func.Crypto1Destroy(crypto1StatePtr);
                crypto1StatePtr = IntPtr.Zero;
                disposed = true;
            }
        }

        ~Crapto1()
        {
            // Do not re-create Dispose clean-up code here.
            // Calling Dispose(false) is optimal in terms of
            // readability and maintainability.
            Dispose(false);
        }
    }
}
