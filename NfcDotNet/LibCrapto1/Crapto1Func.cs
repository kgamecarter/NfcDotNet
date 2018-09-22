using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NfcDotNet.LibCrapto1
{
    public class Crapto1Func
    {
        public const uint LF_POLY_ODD = 0x29CE5C;
        public const uint LF_POLY_EVEN = 0x870804;

        [DllImport("Crapto1.dll", EntryPoint = "crypto1_create", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Crypto1Create(ulong key);

        [DllImport("Crapto1.dll", EntryPoint = "crypto1_destroy", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Crypto1Destroy(IntPtr ptr);

        [DllImport("Crapto1.dll", EntryPoint = "crypto1_bit", CallingConvention = CallingConvention.Cdecl)]
        public static extern byte Crypto1Bit(IntPtr s, byte v, int is_encrypted);

        [DllImport("Crapto1.dll", EntryPoint = "crypto1_byte", CallingConvention = CallingConvention.Cdecl)]
        public static extern byte Crypto1Byte(IntPtr s, byte v, int is_encrypted);

        [DllImport("Crapto1.dll", EntryPoint = "crypto1_word", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint Crypto1Word(IntPtr s, uint v, int is_encrypted);


        [DllImport("Crapto1.dll", EntryPoint = "prng_successor", CallingConvention = CallingConvention.Cdecl)]
        public static extern uint PrngSuccessor(uint x, uint n);

        public static byte Filter(uint x)
	    {
            uint f;
		    f = 0xf22c0u >> (int)(x & 0xf) & 16u;
		    f |= 0x6c9c0u >> (int)(x >> 4 & 0xf) & 8u;
		    f |= 0x3c8b0u >> (int)(x >> 8 & 0xf) & 4u;
		    f |= 0x1e458u >> (int)(x >> 12 & 0xf) & 2u;
		    f |= 0x0d938u >> (int)(x >> 16 & 0xf) & 1u;
		    return (byte)(0xEC57E80A >> (int)f & 1);
	    }

        public static uint ToUInt32(byte[] a, int offset)
        {
            uint result = 0;
            for (int i = 0; i < 4; i++)
                result = (result << 8) | a[i + offset];
            return result;
        }

        public static byte[] GetBytes(uint v)
        {
            byte[] result = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                result[i] = (byte)v;
                v >>= 8;
            }
            return result;
        }
    }
}
