﻿using Crapto1Sharp;
using Crapto1Sharp.Extensions;
using ManagedLibnfc;
using NfcDotNet.Mifare;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using static Crapto1Sharp.Crypto1;
using static ManagedLibnfc.PInvoke.Libnfc;
using static System.Console;

namespace NfcDotNet
{
    class Program
    {
        static byte[] abtReqa = new byte[1] { 0x26 };
        static byte[] abtSelectAll = new byte[2] { 0x93, 0x20 };
        static byte[] abtSelectTag = new byte[9] { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        static byte[] abtRats = new byte[4] { 0xe0, 0x50, 0x00, 0x00 };
        static byte[] abtHalt = new byte[4] { 0x50, 0x00, 0x00, 0x00 };

        static byte[] abtAuthA = new byte[4] { 0x60, 0x00, 0x00, 0x00 };
        static byte[] abtRead = new byte[4] { 0x30, 0x00, 0x00, 0x00 };


        static NfcDevice device;
        const int MAX_FRAME_LEN = 264;
        const byte CASCADE_BIT = 0x04;
        const byte SAK_FLAG_ATS_SUPPORTED = 0x20;

        static byte[] abtRx = new byte[MAX_FRAME_LEN];
        
        static void Main(string[] args)
        {
            byte[] abtRawUid = new byte[12];
            byte[] abtAtqa = new byte[2];
            byte abtSak = 0;
            byte[] abtAts = new byte[MAX_FRAME_LEN];
            uint szAts = 0;
            bool isoAtsSupported = false;
            bool forceRats = false;
            uint szCL = 1;
            try
            {
                using (var context = new NfcContext())
                using (device = context.OpenDevice()) // Try to open the NFC reader
                {
                    // Initialise NFC device as "initiator"
                    device.InitiatorInit();
                    // Configure the CRC
                    device.DeviceSetPropertyBool(NfcProperty.HandleCrc, false);
                    // Use raw send/receive methods
                    device.DeviceSetPropertyBool(NfcProperty.EasyFraming, false);
                    // Disable 14443-4 autoswitching
                    device.DeviceSetPropertyBool(NfcProperty.AutoIso14443_4, false);
                    WriteLine("NFC reader: {0} opened", device.Name);
                    WriteLine();
                    // Send the 7 bits request command specified in ISO 14443A (0x26)
                    TransmitBits(abtReqa, 7);
                    Array.Copy(abtRx, abtAtqa, 2);
                    // Anti-collision
                    TransmitBytes(abtSelectAll, 2);
                    // Check answer
                    if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0)
                        WriteLine("WARNING: BCC check failed!");
                    // Save the UID CL1
                    Array.Copy(abtRx, abtRawUid, 4);


                    //Prepare and send CL1 Select-Command
                    Array.Copy(abtRx, 0, abtSelectTag, 2, 5);
                    Iso14443aCrcAppend(abtSelectTag, 7);
                    TransmitBytes(abtSelectTag, 9);
                    abtSak = abtRx[0];

                    #region CL
                    // Test if we are dealing with a CL2
                    if ((abtSak & CASCADE_BIT) != 0)
                    {
                        szCL = 2;// or more
                                 // Check answer
                        if (abtRawUid[0] != 0x88)
                            WriteLine("WARNING: Cascade bit set but CT != 0x88!");
                    }

                    if (szCL == 2)
                    {
                        // We have to do the anti-collision for cascade level 2

                        // Prepare CL2 commands
                        abtSelectAll[0] = 0x95;

                        // Anti-collision
                        TransmitBytes(abtSelectAll, 2);

                        // Check answer
                        if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0)
                            WriteLine("WARNING: BCC check failed!");

                        // Save UID CL2
                        Array.Copy(abtRx, 0, abtRawUid, 4, 4);

                        // Selection
                        abtSelectTag[0] = 0x95;
                        Array.Copy(abtRx, 0, abtSelectTag, 2, 5);
                        Iso14443aCrcAppend(abtSelectTag, 7);
                        TransmitBytes(abtSelectTag, 9);
                        abtSak = abtRx[0];

                        // Test if we are dealing with a CL3
                        if ((abtSak & CASCADE_BIT) != 0)
                        {
                            szCL = 3;
                            // Check answer
                            if (abtRawUid[0] != 0x88)
                                WriteLine("WARNING: Cascade bit set but CT != 0x88!");
                        }

                        if (szCL == 3)
                        {
                            // We have to do the anti-collision for cascade level 3

                            // Prepare and send CL3 AC-Command
                            abtSelectAll[0] = 0x97;
                            TransmitBytes(abtSelectAll, 2);

                            // Check answer
                            if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0)
                                WriteLine("WARNING: BCC check failed!");

                            // Save UID CL3
                            Array.Copy(abtRx, 0, abtRawUid, 8, 4);

                            // Prepare and send final Select-Command
                            abtSelectTag[0] = 0x97;
                            Array.Copy(abtRx, 0, abtSelectTag, 2, 5);
                            Iso14443aCrcAppend(abtSelectTag, 7);
                            TransmitBytes(abtSelectTag, 9);
                            abtSak = abtRx[0];
                        }
                    }
                    #endregion

                    // Request ATS, this only applies to tags that support ISO 14443A-4
                    if ((abtRx[0] & SAK_FLAG_ATS_SUPPORTED) != 0)
                        isoAtsSupported = true;
                    if ((abtRx[0] & SAK_FLAG_ATS_SUPPORTED) != 0 || forceRats)
                    {
                        Iso14443aCrcAppend(abtRats, 2);
                        int szRx = TransmitBytes(abtRats, 4);
                        if (szRx >= 0)
                        {
                            Array.Copy(abtRx, abtAts, szRx);
                            szAts = (uint)szRx;
                        }
                    }

                    WriteLine();
                    WriteLine("驗證Block 0");
                    // 驗證 Block 0
                    Iso14443aCrcAppend(abtAuthA, 2);
                    TransmitBytes(abtAuthA, 4);
                    // 自己控制 Parity bit
                    device.DeviceSetPropertyBool(NfcProperty.HandleParity, false);

                    var nt = abtRx.ToUInt32();
                    var uid = abtRawUid.ToUInt32();
                    Write("           Nt: ");
                    PrintHex(abtRx, 4);
                    var crapto1 = new Crypto1(0xFFFFFFFFFFFFu);
                    // 初始化 crapto1 狀態 feed in uid^nt and drop keystream in the first round
                    crapto1.Crypto1Word(uid ^ nt);
                    // 自訂讀卡機端nonce
                    var nr = 0x01020304u;
                    // Ar 為 suc2(nt)
                    var ar = PrngSuccessor(nt, 64);
                    // 加密 Nr,suc2(Nt) 和 parity bit
                    var enNrAr = nr.GetBytes().Concat(ar.GetBytes()).ToArray();
                    var enNrArParity = new byte[8];
                    crapto1.Encrypt(enNrAr, enNrArParity, 0, 4, true);
                    crapto1.Encrypt(enNrAr, enNrArParity, 4, 4);
                    Write("[Nr,suc2(Nt)]: ");
                    PrintHex(enNrAr, 8);
                    // 送出[Nr,suc2(Nt)]
                    device.InitiatorTransceiveBits(enNrAr, 64, enNrArParity, abtRx, MAX_FRAME_LEN, null);
                    var enAt = new byte[4];
                    Array.Copy(abtRx, enAt, 4);
                    Write("   [suc3(Nt)]: ");
                    PrintHex(enAt, 4);
                    // 解密[at]
                    var at = enAt.ToUInt32() ^ crapto1.Crypto1Word();
                    WriteLine("At: {0:x8} == suc3(Nt):{1:x8}", at, PrngSuccessor(nt, 96));
                    // 讀取 Block
                    for (byte i = 0; i < 4; i++)
                        ReadBlock(crapto1, i);
                    WriteLine();
                    WriteLine("Nested驗證 Block 4");
                    // Nested驗證 Block 4
                    abtAuthA[1] = 4;
                    Iso14443aCrcAppend(abtAuthA, 2);
                    var enAuth = abtAuthA.ToArray();
                    var enAuthParity = new byte[4];
                    crapto1.Encrypt(enAuth, enAuthParity, 0, 4);
                    device.InitiatorTransceiveBits(enAuth, 32, enAuthParity, abtRx, MAX_FRAME_LEN, null);

                    // 開始Nested驗證的新crypto1密鑰
                    crapto1 = new Crypto1(0xFFFFFFFFFFFFu);
                    Write("     未解密Nt: ");
                    PrintHex(abtRx, 4);
                    var enNt = abtRx.ToUInt32();
                    // 初始化 crapto1 狀態 用加密的Nt，並解出明文nt
                    nt = enNt ^ crapto1.Crypto1Word(uid ^ enNt, true);
                    Write("           Nt: ");
                    PrintHex(nt.GetBytes(), 4);
                    // 自訂讀卡機端nonce
                    nr = 0x01020304u;
                    // Ar 為 suc2(nt)
                    ar = PrngSuccessor(nt, 64);
                    // 加密 Nr,suc2(Nt) 和 parity bit
                    enNrAr = nr.GetBytes().Concat(ar.GetBytes()).ToArray();
                    enNrArParity = new byte[8];
                    crapto1.Encrypt(enNrAr, enNrArParity, 0, 4, true);
                    crapto1.Encrypt(enNrAr, enNrArParity, 4, 4);
                    Write("[Nr,suc2(Nt)]: ");
                    PrintHex(enNrAr, 8);
                    // 送出[Nr,suc2(Nt)]
                    var res = device.InitiatorTransceiveBits(enNrAr, 64, enNrArParity, abtRx, MAX_FRAME_LEN, null);
                    enAt = new byte[4];
                    Array.Copy(abtRx, enAt, 4);
                    Write("   [suc3(Nt)]: ");
                    PrintHex(enAt, 4);
                    // 解密[at]
                    at = enAt.ToUInt32() ^ crapto1.Crypto1Word();
                    WriteLine("At: {0:x8} == suc3(Nt):{1:x8}", at, PrngSuccessor(nt, 96));

                    // 寫入 Block4
                    WriteBlock(crapto1, 4, new byte[16] { 65, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
                        
                    // 讀取 Block
                    for (byte i = 4; i < 8; i++)
                        ReadBlock(crapto1, i);

                    WriteLine();

                    // device.DeviceSetPropertyBool(NfcProperty.HandleParity, true);
                    // Done, halt the tag now
                    Iso14443aCrcAppend(abtHalt, 2);
                    TransmitBytes(abtHalt, 4);
                }
            }
            catch(Exception ex)
            {
                WriteLine(ex.Message);
                Environment.Exit(1);
            }
            WriteLine();
            WriteLine("Found tag with");
            Write(" UID: ");
            switch (szCL)
            {
                case 1:
                    Write("{0:x2}{1:x2}{2:x2}{3:x2}", abtRawUid[0], abtRawUid[1], abtRawUid[2], abtRawUid[3]);
                    break;
                case 2:
                    Write("{0:x2}{1:x2}{2:x2}", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
                    Write("{0:x2}{1:x2}{2:x2}{3:x2}", abtRawUid[4], abtRawUid[5], abtRawUid[6], abtRawUid[7]);
                    break;
                case 3:
                    Write("{0:x2}{1:x2}{2:x2}", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
                    Write("{0:x2}{1:x2}{2:x2}", abtRawUid[5], abtRawUid[6], abtRawUid[7]);
                    Write("{0:x2}{1:x2}{2:x2}{3:x2}", abtRawUid[8], abtRawUid[9], abtRawUid[10], abtRawUid[11]);
                    break;
            }
            WriteLine();
            WriteLine("ATQA: {0:x2}{1:x2}", abtAtqa[1], abtAtqa[0]);
            WriteLine(" SAK: {0:x2}", abtSak);
            if (szAts > 1)
            { // if = 1, it's not actual ATS but error code
                if (forceRats && !isoAtsSupported)
                    WriteLine(" RATS forced");
                Write(" ATS: ");
                PrintHex(abtAts, szAts);
            }

            ReadLine();
        }

        static void ReadBlock(Crypto1 crapto1, byte b)
        {
            abtRead[1] = b;
            Iso14443aCrcAppend(abtRead, 2);
            var enAbtRead = abtRead.ToArray();
            var enAbtReadParity = new byte[4];
            crapto1.Encrypt(enAbtRead, enAbtReadParity, 0, 4);
            device.InitiatorTransceiveBits(enAbtRead, 32, enAbtReadParity, abtRx, MAX_FRAME_LEN, null);
            var block = new byte[18]; // 16byte data + 2byte crc
            for (int i = 0; i < 18; i++)
                block[i] = (byte)(abtRx[i] ^ crapto1.Crypto1Byte());
            Write("      Block{0,2}: ", b);
            PrintHex(block, 16);
        }

        static void WriteBlock(Crypto1 crapto1, byte b, byte[] blockData)
        {
            var enWrite = new byte[4] { 0xA0, b, 0, 0 };
            Iso14443aCrcAppend(enWrite, 2);
            var enWriteParity = new byte[4];
            crapto1.Encrypt(enWrite, enWriteParity, 0, 4);
            var resbits = device.InitiatorTransceiveBits(enWrite, 32, enWriteParity, abtRx, MAX_FRAME_LEN, null);
            var res = 0;
            for (int i = 0; i < 4; i++)
                res |= ((abtRx[0] >> i) ^ crapto1.Crypto1Bit()) << i;
            WriteLine("Write Cmd : " + res.ToString("x2"));
            if (res != 0x0A && res != 0x0E) // 0x0A ACK, 0x0E NAK
                throw new Exception("Cmd Error: " + res.ToString("x2"));

            var enBlock = new byte[18]; // 16byte data + 2byte crc
            var enBlockParity = new byte[18];
            if (blockData != null)
                Array.Copy(blockData, enBlock, blockData.Length > 16 ? 16 : blockData.Length);
            Iso14443aCrcAppend(enBlock, 16);
            Write("Write Block{0,2}: ", b);
            PrintHex(enBlock, 16);
            crapto1.Encrypt(enBlock, enBlockParity, 0, 18);
            resbits = device.InitiatorTransceiveBits(enBlock, 144, enBlockParity, abtRx, MAX_FRAME_LEN, null);
            res = 0;
            for (int i = 0; i < 4; i++)
                res |= ((abtRx[0] >> i) ^ crapto1.Crypto1Bit()) << i;
            WriteLine("Write data: " + res.ToString("x2"));
            if (res != 0x0A && res != 0x0E) // 0x0A ACK, 0x0E NAK
                throw new Exception("Cmd Error: " + res.ToString("x2"));

            //var enTransfer = new byte[4] { 0xB0, b, 0, 0 };
            //Nfc.Iso14443aCrcAppend(enTransfer, 2);
            //var enTransferParity = new byte[4];
            //crapto1.Encrypt(enTransfer, enTransferParity, 0, 4);
            //res = device.InitiatorTransceiveBits(enTransfer, 32, enTransferParity, abtRx, MAX_FRAME_LEN, null);
        }

        static bool quietOutput = false;
        static bool timed = false;
        static int TransmitBits(byte[] pbtTx, uint szTxBits)
        {
            // Show transmitted command
            if (!quietOutput)
            {
                Write("Sent bits:     ");
                PrintHexBits(pbtTx, szTxBits);
            }
            int szRxBits;
            // Transmit the bit frame command, we don't use the arbitrary parity feature
            if (timed)
            {
                uint cycles = 0;
                if ((szRxBits = device.InitiatorTransceiveBitsTimed(pbtTx, szTxBits, null, abtRx, MAX_FRAME_LEN, null, ref cycles)) < 0)
                    throw new Exception("Error: No tag available");
                if ((!quietOutput) && (szRxBits > 0))
                {
                    WriteLine("Response after {0} cycles", cycles);
                }
            }
            else
            {
                if ((szRxBits = device.InitiatorTransceiveBits(pbtTx, szTxBits, null, abtRx, MAX_FRAME_LEN, null)) < 0)
                    throw new Exception("Error: No tag available");
            }
            // Show received answer
            if (!quietOutput)
            {
                Write("Received bits: ");
                PrintHexBits(abtRx, (uint)szRxBits);
            }
            // Succesful transfer
            return szRxBits;
        }

        static int TransmitBytes(byte[] pbtTx, uint szTx)
        {
            // Show transmitted command
            if (!quietOutput)
            {
                Write("Sent bits:     ");
                PrintHex(pbtTx, szTx);
            }
            int szRx;
            // Transmit the command bytes
            if (timed)
            {
                uint cycles = 0;
                if ((szRx = device.InitiatorTransceiveBytesTimed(pbtTx, szTx, abtRx, MAX_FRAME_LEN, ref cycles)) < 0)
                    return szRx;
                if ((!quietOutput) && (szRx > 0))
                {
                    WriteLine("Response after {0} cycles", cycles);
                }
            }
            else
            {
                if ((szRx = device.InitiatorTransceiveBytes(pbtTx, szTx, abtRx, MAX_FRAME_LEN, 0)) < 0)
                    return szRx;
            }
            // Show received answer
            if (!quietOutput)
            {
                Write("Received bits: ");
                PrintHex(abtRx, (uint)szRx);
            }
            // Succesful transfer
            return szRx;
        }

        public static void PrintHexBits(byte[] data, uint szBits)
        {
            uint uRemainder;
            uint szBytes = szBits / 8;

            for (uint i = 0; i < szBytes; i++)
                Write("{0:x2}  ", data[i]);

            uRemainder = szBits % 8;
            // Print the rest bits
            if (uRemainder != 0)
            {
                if (uRemainder < 5)
                    Write("{0:x1} ({1} bits)", data[szBytes], uRemainder);
                else
                    Write("{0:x2} ({1} bits)", data[szBytes], uRemainder);
            }
            WriteLine();
        }

        public static void PrintHex(byte[] pbtData, uint szBytes)
        {
            for (uint i = 0; i < szBytes; i++)
                Write("{0:x2}  ", pbtData[i]);
            WriteLine();
        }
    }
}
