using Crapto1Sharp;
using Crapto1Sharp.Extensions;
using ManagedLibnfc;
using NfcDotNet.Mifare;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NfcDotNet
{
    public class Test
    {
        static Random rnd = new Random();
        public static int FilterFunctionTest()
        {
            var s = new byte[]
            {
                0x00,
                0x80,
                0x20,
                0xA0,
                0x08,
                0x88,
                0x28,
                0xA8,
                0x02,
                0x82,
                0x22,
                0xA2,
                0x0A,
                0x8A,
                0x2A,
                0xAA
            };
            ulong key = 0;
            for (int i = 0; i < 5; i++)
                key = key << 8 | (byte)rnd.Next(0xFF);
            key <<= 8;
            Console.WriteLine("0x{0:x10}", key);
            for (int i = s.Length - 1; i >= 0; i--)
                Console.Write("{0:x2} ", s[i]);
            Console.WriteLine();
            int fb = 0;
            for (int i = s.Length - 1; i >= 0; i--)
            {
                var c = new Crypto1(key | (ulong)s[i]);
                var ks = c.PeekCrypto1Bit();
                fb = fb << 1 | ks;
                Console.Write(" {0} ", ks);
            }
            Console.WriteLine();
            Console.WriteLine("0x{0:x4}", fb);
            return fb;
        }

        public static void MifareTest()
        {
            using (var context = new NfcContext())
            using (var device = context.OpenDevice()) // Try to open the NFC reader
            {
                MifareClassic mfc = new MifareClassic(device);
                mfc.InitialDevice();
                mfc.SelectCard();
                mfc.Authentication(0, KeyType.KeyA, 0xFFFFFFFFFFFFu);
                var block0 = mfc.ReadBlock(0);
                Program.PrintHex(block0, 16);
                mfc.Authentication(1, KeyType.KeyA, 0xFFFFFFFFFFFFu);
                mfc.WriteBlock(4, new byte[16] { 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                var block4 = mfc.ReadBlock(4);
                Program.PrintHex(block4, 16);
                Console.ReadLine();
            }
        }

        public static (Dictionary<(byte, KeyType), ulong?>, byte[][]) KeyMapDump(string path)
        {
            var keys = File.ReadAllLines(path)
                .Where(line => !string.IsNullOrEmpty(line))
                .Select(line => Convert.ToUInt64(line.Trim(), 16))
                .ToArray();
            var data = new byte[64][];
            var dic = new Dictionary<(byte, KeyType), ulong?>();
            using (var context = new NfcContext())
            using (var device = context.OpenDevice()) // Try to open the NFC reader
            {
                MifareClassic mfc = new MifareClassic(device);
                mfc.InitialDevice();
                for (byte i = 0; i < 16; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        var type = (KeyType)j;
                        var skip = i * 2 + j;
                        foreach (var key in keys.Skip(skip).Concat(keys.Take(skip)))
                        {
                            try
                            {
                                if (mfc.Uid == null)
                                    mfc.SelectCard();
                                dic[(i, type)] = null;
                                if (mfc.Authentication(i, type, key))
                                {
                                    dic[(i, type)] = key;
                                    for (int k = 0; k < 4; k++)
                                    {
                                        var block = (byte)(i * 4 + k);
                                        if (data[block] == null)
                                            data[block] = mfc.ReadBlock(block);
                                    }
                                    var keyBlock = i * 4 + 3;
                                    if (data[keyBlock] != null)
                                    {
                                        var offset = 5;
                                        if (type == KeyType.KeyB)
                                            offset = 15;
                                        for (int k = 0; k < 6; k++)
                                            data[keyBlock][offset - k] = (byte)(key >> (k * 8));
                                    }
                                    break;
                                }
                            }
                            catch
                            { }
                        }
                    }
                }
            }
            return (dic, data);
        }
    }
}
