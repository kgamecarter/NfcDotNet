using NfcDotNet.LibCrapto1;
using NfcDotNet.LibNfc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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
        

        static NfcDevice device;
        const int MAX_FRAME_LEN = 264;
        const byte CASCADE_BIT = 0x04;
        const byte SAK_FLAG_ATS_SUPPORTED = 0x20;

        static byte[] abtRx = new byte[MAX_FRAME_LEN];


        static void Test()
        {
            //shared informationn
            ulong key = 0xffffffffffffUL;
            uint uid = 0x9c599b32;


            //information available to the tag
            uint nonce = 0xA55D950B;
            uint rn_enc = 0x98d76b77;
            uint rr_enc = 0xd6c6e870;

            //information available to the reader
            uint nonce_enc = 0x5a920d85;
            uint rn = 0x77B78918;
            uint tr_enc = 0xca7e0b63;

            //TAG
            Console.WriteLine("from the TAG's point of view:");
            using (var crapto1 = new Crapto1(key))
            {
                Console.WriteLine("\tsending [tag nonce]   : {0:x8}", nonce ^ crapto1.Crypto1Word(uid ^ nonce, false));
                Console.WriteLine("\treceived reader nonce : {0:x8}", rn_enc ^ crapto1.Crypto1Word(rn_enc, true));
                Console.WriteLine("\treceived reader reply : {0:x8}", rr_enc ^ crapto1.Crypto1Word(0, false));
                Console.WriteLine("\tsending [tag reply]   : {0:x8}", Crapto1Func.PrngSuccessor(nonce, 96) ^ crapto1.Crypto1Word(0, false));
            }

            //READER
            Console.WriteLine();
            Console.WriteLine("from the READER's point of view:");
            using (var crapto1 = new Crapto1(key))
            {
                Console.WriteLine("\treceived tag nonce     : {0:x8}", nonce = (nonce_enc ^ crapto1.Crypto1Word(uid ^ nonce_enc, true)));
                Console.WriteLine("\tsending [reader nonce] : {0:x8}", rn ^ crapto1.Crypto1Word(rn, false));
                Console.WriteLine("\tsending [reader reply] : {0:x8}", Crapto1Func.PrngSuccessor(nonce, 64) ^ crapto1.Crypto1Word(0, false));
                Console.WriteLine("\treceived tag reply     : {0:x8}", tr_enc ^ crapto1.Crypto1Word(0, false));
            }
            Console.ReadLine();
        }

        static void Main(string[] args)
        {
            byte[] abtRawUid = new byte[12];
            byte[] abtAtqa = new byte[2];
            byte abtSak = 0;
            byte[] abtAts = new byte[MAX_FRAME_LEN];
            uint szAts = 0;
            bool isoAtsSupported = false;
            bool forceRats = false;

            IntPtr context;
            Nfc.Init(out context);
            if (context == IntPtr.Zero)
            {
                Console.Error.WriteLine("Unable to init libnfc (malloc)");
                Environment.Exit(1);
            }

            // Try to open the NFC reader
            var devicePointer = Nfc.Open(context, null);
            if (devicePointer == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error opening NFC reader");
                Nfc.Exit(context);
                Environment.Exit(1);
            }
            device = new NfcDevice(devicePointer);

            // Initialise NFC device as "initiator"
            if (device.InitiatorInit() < 0)
            {
                device.Perror("nfc_initiator_init");
                device.Close();
                Nfc.Exit(context);
                Environment.Exit(1);
            }

            if (device.DeviceSetPropertyBool(NfcProperty.HandleCrc, false) < 0 ||    // Configure the CRC
                device.DeviceSetPropertyBool(NfcProperty.EasyFraming, false) < 0 ||  // Use raw send/receive methods
                device.DeviceSetPropertyBool(NfcProperty.AutoIso14443_4, false) < 0) // Disable 14443-4 autoswitching
            {
                device.Perror("nfc_device_set_property_bool");
                device.Close();
                Nfc.Exit(context);
                Environment.Exit(1);
            }
            Console.WriteLine("NFC reader: {0} opened", device.Name);
            Console.WriteLine();

            // Send the 7 bits request command specified in ISO 14443A (0x26)
            if (!TransmitBits(abtReqa, 7))
            {
                Console.WriteLine("Error: No tag available");
                Nfc.Close(devicePointer);
                Nfc.Exit(context);
                Environment.Exit(1);
            }
            Array.Copy(abtRx, abtAtqa, 2);

            // Anti-collision
            TransmitBytes(abtSelectAll, 2);

            // Check answer
            if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0)
            {
                Console.WriteLine("WARNING: BCC check failed!");
            }

            // Save the UID CL1
            Array.Copy(abtRx, abtRawUid, 4);

            //Prepare and send CL1 Select-Command
            Array.Copy(abtRx, 0, abtSelectTag, 2, 5);
            Nfc.Iso14443aCrcAppend(abtSelectTag, 7);
            TransmitBytes(abtSelectTag, 9);
            abtSak = abtRx[0];

            uint szCL = 1;
            // Test if we are dealing with a CL2
            if ((abtSak & CASCADE_BIT) != 0)
            {
                szCL = 2;// or more
                         // Check answer
                if (abtRawUid[0] != 0x88)
                {
                    Console.WriteLine("WARNING: Cascade bit set but CT != 0x88!\n");
                }
            }

            #region CL
            if (szCL == 2)
            {
                // We have to do the anti-collision for cascade level 2

                // Prepare CL2 commands
                abtSelectAll[0] = 0x95;

                // Anti-collision
                TransmitBytes(abtSelectAll, 2);

                // Check answer
                if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0)
                {
                    Console.WriteLine("WARNING: BCC check failed!\n");
                }

                // Save UID CL2
                Array.Copy(abtRx, 0, abtRawUid, 4, 4);

                // Selection
                abtSelectTag[0] = 0x95;
                Array.Copy(abtRx, 0, abtSelectTag, 2, 5);
                Nfc.Iso14443aCrcAppend(abtSelectTag, 7);
                TransmitBytes(abtSelectTag, 9);
                abtSak = abtRx[0];

                // Test if we are dealing with a CL3
                if ((abtSak & CASCADE_BIT) != 0)
                {
                    szCL = 3;
                    // Check answer
                    if (abtRawUid[0] != 0x88)
                    {
                        Console.WriteLine("WARNING: Cascade bit set but CT != 0x88!\n");
                    }
                }

                if (szCL == 3)
                {
                    // We have to do the anti-collision for cascade level 3

                    // Prepare and send CL3 AC-Command
                    abtSelectAll[0] = 0x97;
                    TransmitBytes(abtSelectAll, 2);

                    // Check answer
                    if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0)
                    {
                        Console.WriteLine("WARNING: BCC check failed!\n");
                    }

                    // Save UID CL3
                    Array.Copy(abtRx, 0, abtRawUid, 8, 4);

                    // Prepare and send final Select-Command
                    abtSelectTag[0] = 0x97;
                    Array.Copy(abtRx, 0, abtSelectTag, 2, 5);
                    Nfc.Iso14443aCrcAppend(abtSelectTag, 7);
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
                Nfc.Iso14443aCrcAppend(abtRats, 2);
                int szRx = TransmitBytes(abtRats, 4);
                if (szRx >= 0)
                {
                    Array.Copy(abtRx, abtAts, szRx);
                    szAts = (uint)szRx;
                }
            }

            Nfc.Iso14443aCrcAppend(abtAuthA, 2);
            TransmitBytes(abtAuthA, 4);
            // 自己控制 Parity bit
            device.DeviceSetPropertyBool(NfcProperty.HandleParity, false);

            var nt = Crapto1Func.ToUInt32(abtRx);
            var uid = Crapto1Func.ToUInt32(abtRawUid);
            Console.Write("           Nt: ");
            PrintHex(abtRx, 4);
            using (var crapto1 = new Crapto1(0xFFFFFFFFFFFFu))
            {
                // 初始化 crapto1 狀態 feed in uid^nt and drop keystream in the first round
                crapto1.Crypto1Word(uid ^ nt);
                // 自訂讀卡機端nonce
                var nr = 0x01020304u;
                // Ar 為 suc2(nt)
                var ar = Crapto1Func.PrngSuccessor(nt, 64); 
                // 加密 Nr,suc2(Nt) 和 parity bit
                var enNrAr = Crapto1Func.GetBytes(nr).Concat(Crapto1Func.GetBytes(ar)).ToArray();
                var enNrArParity = new byte[8];
                for (int i = 0; i < 8; i++)
                {
                    // 計算 Parity
                    enNrArParity[i] = Parity.OddParity8(enNrAr[i]);
                    // 加密, 0~3是Nr要帶入Crypto1位移
                    enNrAr[i] ^= crapto1.Crypto1Byte(i < 4 ? enNrAr[i] : (byte)0);
                    // 加密 Parity
                    enNrArParity[i] ^= crapto1.PeekCrypto1Bit(); 
                }
                Console.Write("[Nr,suc2(Nt)]: ");
                PrintHex(enNrAr, 8);
                // 送出[Nr,suc2(Nt)]
                var res = device.InitiatorTransceiveBits(enNrAr, 64, enNrArParity, abtRx, MAX_FRAME_LEN, null);
                var enAt = new byte[4];
                Array.Copy(abtRx, enAt, 4);
                Console.Write("   [suc3(Nt)]: ");
                PrintHex(enAt, 4);
                // 解密[at]
                var at = Crapto1Func.ToUInt32(enAt) ^ crapto1.Crypto1Word();
                Console.WriteLine("At: {0:x8} == suc3(Nt):{1:x8}", at, Crapto1Func.PrngSuccessor(nt, 96));


            }

            // Done, halt the tag now
            Nfc.Iso14443aCrcAppend(abtHalt, 2);
            TransmitBytes(abtHalt, 4);
            Console.WriteLine();
            Console.WriteLine("Found tag with");
            Console.Write(" UID: ");
            switch (szCL)
            {
                case 1:
                    Console.Write("{0:x2}{1:x2}{2:x2}{3:x2}", abtRawUid[0], abtRawUid[1], abtRawUid[2], abtRawUid[3]);
                    break;
                case 2:
                    Console.Write("{0:x2}{1:x2}{2:x2}", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
                    Console.Write("{0:x2}{1:x2}{2:x2}{3:x2}", abtRawUid[4], abtRawUid[5], abtRawUid[6], abtRawUid[7]);
                    break;
                case 3:
                    Console.Write("{0:x2}{1:x2}{2:x2}", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
                    Console.Write("{0:x2}{1:x2}{2:x2}", abtRawUid[5], abtRawUid[6], abtRawUid[7]);
                    Console.Write("{0:x2}{1:x2}{2:x2}{3:x2}", abtRawUid[8], abtRawUid[9], abtRawUid[10], abtRawUid[11]);
                    break;
            }
            Console.WriteLine();
            Console.WriteLine("ATQA: {0:x2}{1:x2}", abtAtqa[1], abtAtqa[0]);
            Console.WriteLine(" SAK: {0:x2}", abtSak);
            if (szAts > 1)
            { // if = 1, it's not actual ATS but error code
                if (forceRats && !isoAtsSupported)
                    Console.WriteLine(" RATS forced");
                Console.Write(" ATS: ");
                PrintHex(abtAts, szAts);
            }
            
            device.Close();
            Nfc.Exit(context);
            Console.ReadLine();
        }

        static bool quietOutput = false;
        static bool timed = false;
        static bool TransmitBits(byte[] pbtTx, uint szTxBits)
        {
            // Show transmitted command
            if (!quietOutput)
            {
                Console.Write("Sent bits:     ");
                PrintHexBits(pbtTx, szTxBits);
            }
            int szRxBits;
            // Transmit the bit frame command, we don't use the arbitrary parity feature
            if (timed)
            {
                uint cycles = 0;
                if ((szRxBits = device.InitiatorTransceiveBitsTimed(pbtTx, szTxBits, null, abtRx, MAX_FRAME_LEN, null, ref cycles)) < 0)
                    return false;
                if ((!quietOutput) && (szRxBits > 0))
                {
                    Console.WriteLine("Response after {0} cycles", cycles);
                }
            }
            else
            {
                if ((szRxBits = device.InitiatorTransceiveBits(pbtTx, szTxBits, null, abtRx, MAX_FRAME_LEN, null)) < 0)
                    return false;
            }
            // Show received answer
            if (!quietOutput)
            {
                Console.Write("Received bits: ");
                PrintHexBits(abtRx, (uint)szRxBits);
            }
            // Succesful transfer
            return true;
        }

        static int TransmitBytes(byte[] pbtTx, uint szTx)
        {
            // Show transmitted command
            if (!quietOutput)
            {
                Console.Write("Sent bits:     ");
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
                    Console.WriteLine("Response after {0} cycles", cycles);
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
                Console.Write("Received bits: ");
                PrintHex(abtRx, (uint)szRx);
            }
            // Succesful transfer
            return szRx;
        }

        static void PrintHexBits(byte[] data, uint szBits)
        {
            uint uRemainder;
            uint szBytes = szBits / 8;

            for (uint i = 0; i < szBytes; i++)
                Console.Write("{0:x2}  ", data[i]);

            uRemainder = szBits % 8;
            // Print the rest bits
            if (uRemainder != 0)
            {
                if (uRemainder < 5)
                    Console.Write("{0:x1} ({1} bits)", data[szBytes], uRemainder);
                else
                    Console.Write("{0:x2} ({1} bits)", data[szBytes], uRemainder);
            }
            Console.WriteLine();
        }

        static void PrintHex(byte[] pbtData, uint szBytes)
        {
            for (uint i = 0; i < szBytes; i++)
                Console.Write("{0:x2}  ", pbtData[i]);
            Console.WriteLine();
        }
    }
}
