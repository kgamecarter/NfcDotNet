using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Crapto1Sharp;
using Crapto1Sharp.Extensions;
using ManagedLibnfc;
using ManagedLibnfc.PInvoke;

namespace NfcDotNet.Mifare
{
    public class MifareClassic
    {
        const int MAX_FRAME_LEN = 264;

        private byte[] rxBuffer = new byte[256];

        public Crypto1 Crypto1 { get; set; }

        private byte _sector;

        public byte Sector
        {
            get
            { return _sector; }
        }

        public NfcDevice Device { get; set; }

        public uint Uid { get; set; }

        public byte Sak { get; set; }

        public MifareClassic(NfcDevice device)
        {
            Device = device;
        }

        public void InitialDevice()
        {
            // Initialise NFC device as "initiator"
            Device.InitiatorInit();
            // Configure the CRC
            Device.DeviceSetPropertyBool(NfcProperty.HandleCrc, false);
            // Use raw send/receive methods
            Device.DeviceSetPropertyBool(NfcProperty.EasyFraming, false);
            // Disable 14443-4 autoswitching
            Device.DeviceSetPropertyBool(NfcProperty.AutoIso14443_4, false);
        }

        public bool SelectCard()
        {
            var reqa = new byte[1] { 0x26 };
            Device.InitiatorTransceiveBits(reqa, 7, null, rxBuffer, MAX_FRAME_LEN, null);
            var selectAll = new byte[2] { 0x93, 0x20 };
            Device.InitiatorTransceiveBytes(selectAll, 2, rxBuffer, MAX_FRAME_LEN, 0);
            if ((rxBuffer[0] ^ rxBuffer[1] ^ rxBuffer[2] ^ rxBuffer[3] ^ rxBuffer[4]) != 0)
                return false;
            Uid = rxBuffer.ToUInt32();
            var selectTag = new byte[9] { 0x93, 0x70, rxBuffer[0], rxBuffer[1], rxBuffer[2], rxBuffer[3], rxBuffer[4], 0x00, 0x00 };
            Libnfc.Iso14443aCrcAppend(selectTag, 7);
            Device.InitiatorTransceiveBytes(selectTag, 9, rxBuffer, MAX_FRAME_LEN, 0);
            Sak = rxBuffer[0];
            return true;
        }

        public void Authentication(byte sector, KeyType keyType, ulong key)
        {
            var auth = new byte[4]
            {
                keyType == KeyType.KeyA ? (byte)0x60 : (byte)0x61,
                (byte)(sector * 4), 0, 0
            };
            Libnfc.Iso14443aCrcAppend(auth, 2);
            var nt = 0u;
            var crapto1 = new Crypto1(key);
            if (Crypto1 == null) // 初次驗證
            {
                Device.DeviceSetPropertyBool(NfcProperty.HandleParity, true);
                Device.InitiatorTransceiveBytes(auth, 4, rxBuffer, MAX_FRAME_LEN, 0);
                Device.DeviceSetPropertyBool(NfcProperty.HandleParity, false);
                nt = rxBuffer.ToUInt32();
                crapto1.Crypto1Word(Uid ^ nt);
            }
            else // Nested 驗證
            {
                var authParity = new byte[4];
                Crypto1.Encrypt(auth, authParity, 0, 4);
                Device.InitiatorTransceiveBits(auth, 32, authParity, rxBuffer, MAX_FRAME_LEN, null);
                nt = rxBuffer.ToUInt32();
                nt = nt ^ crapto1.Crypto1Word(Uid ^ nt, true);
                Crypto1 = null;
            }
            var nr = 0x01020304u;
            var ar = Crypto1.PrngSuccessor(nt, 64);
            var enNrAr = nr.GetBytes().Concat(ar.GetBytes()).ToArray();
            var enNrArParity = new byte[8];
            crapto1.Encrypt(enNrAr, enNrArParity, 0, 4, true);
            crapto1.Encrypt(enNrAr, enNrArParity, 4, 4);
            Device.InitiatorTransceiveBits(enNrAr, 64, enNrArParity, rxBuffer, MAX_FRAME_LEN, null);
            var at = rxBuffer.ToUInt32() ^ crapto1.Crypto1Word();
            if (at != Crypto1.PrngSuccessor(nt, 96))
                throw new Exception("At error");
            Crypto1 = crapto1;
            _sector = sector;
        }

        public byte[] ReadBlock(byte b)
        {
            if (b / 4 != _sector || Crypto1 == null)
                throw new Exception("Not auth");
            var read = new byte[4] { 0x30, b, 0, 0 };
            Libnfc.Iso14443aCrcAppend(read, 2);
            var readParity = new byte[4];
            Crypto1.Encrypt(read, readParity, 0, 4);
            Device.InitiatorTransceiveBits(read, 32, readParity, rxBuffer, MAX_FRAME_LEN, null);
            for (int i = 0; i < 18; i++) // 16byte data + 2byte crc
                rxBuffer[i] ^= Crypto1.Crypto1Byte();
            return rxBuffer.Take(16).ToArray();
        }

        public void WriteBlock(byte b, byte[] blockData)
        {
            if (b / 4 != _sector || Crypto1 == null)
                throw new Exception("Not auth");
            var write = new byte[4] { 0xA0, b, 0, 0 };
            Libnfc.Iso14443aCrcAppend(write, 2);
            var writeParity = new byte[4];
            Crypto1.Encrypt(write, writeParity, 0, 4);
            var resbits = Device.InitiatorTransceiveBits(write, 32, writeParity, rxBuffer, MAX_FRAME_LEN, null);
            var res = 0;
            for (int i = 0; i < 4; i++)
                res |= ((rxBuffer[0] >> i) ^ Crypto1.Crypto1Bit()) << i;
            if (res != 0x0A && res != 0x0E) // 0x0A ACK, 0x0E NAK
                throw new Exception("Cmd Error: " + res.ToString("x2"));

            var block = new byte[18]; // 16byte data + 2byte crc
            var blockParity = new byte[18];
            if (blockData != null)
                Array.Copy(blockData, block, blockData.Length > 16 ? 16 : blockData.Length);
            Libnfc.Iso14443aCrcAppend(block, 16);
            Crypto1.Encrypt(block, blockParity, 0, 18);
            resbits = Device.InitiatorTransceiveBits(block, 144, blockParity, rxBuffer, MAX_FRAME_LEN, null);
            res = 0;
            for (int i = 0; i < 4; i++)
                res |= ((rxBuffer[0] >> i) ^ Crypto1.Crypto1Bit()) << i;
            if (res != 0x0A && res != 0x0E) // 0x0A ACK, 0x0E NAK
                throw new Exception("Cmd Error: " + res.ToString("x2"));
        }
    }

    public enum KeyType
    {
        KeyA,
        KeyB
    }
}
