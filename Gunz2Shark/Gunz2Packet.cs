using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Web.Script.Serialization;
using Ionic.Zlib;
namespace Gunz2Shark
{

    struct Gunz2Flags
    {
       public bool keepalive;
       public bool isping;
       public bool unkFlag3;
       public bool encrypted;
       public bool compressed;
       public uint size;
    }

    class Gunz2Packet
    {
        public UInt32 flagsraw; //Gunz2Flags without flags set
        public Gunz2Flags flags; //Struct for holding set flags
        public UInt32 pktCounter; //packet order (not used?)
        public UInt16 pktID; //opcodeid
        public UInt16 checksum; //crc16
        public UInt32 datalen; //length of actual data
        public UInt16 pktID2; //packet id again
        public byte[] data;

        public Gunz2Packet(byte[] buf, byte[] _cryptKey)
        {
            flagsraw = BitConverter.ToUInt32(buf, 0);
            flags = new Gunz2Flags();
            flags.keepalive = (byte)((flagsraw >> 0) & 1) == 1;
            flags.isping = (byte)((flagsraw >> 1) & 1) == 1; //used for keepalive. Normal is set to false for keepalive packets.
            flags.unkFlag3 = (byte)((flagsraw >> 2) & 1) == 1;
            flags.encrypted = (byte)((flagsraw >> 3) & 1) == 1;
            flags.compressed = (byte)((flagsraw >> 4) & 1) == 1;
            flags.size = (uint)(0x7FFFFF & (flagsraw >> 5));
            // how to check if it it's encrypted.
            if (flags.encrypted)
            {
                Decrypt(buf, 12, (uint)buf.Length - 12, _cryptKey);
            }

            if (flags.compressed && flags.encrypted && flags.size < 65535)
            {
                uint fullSize = BitConverter.ToUInt32(buf, 12);
                byte[] decompressedBuffer = new byte[fullSize - 12];
                byte[] cpyArray = new byte[flags.size - 16];
                Buffer.BlockCopy(buf, 16, cpyArray, 0, buf.Length - 16);
                //Console.WriteLine("This packet is compressed. Length: {0}", fullSize - 12);
                using (ZlibStream zlib = new ZlibStream(new MemoryStream(cpyArray), CompressionMode.Decompress))
                {
                    zlib.Read(decompressedBuffer, 0, (int)fullSize - 12);
                }
                Array.Resize(ref buf, (int)fullSize);
                Buffer.BlockCopy(decompressedBuffer, 0, buf, 12, (int)fullSize - 12);
            }
            data = buf;
            if (!flags.isping)
            {
                pktCounter = BitConverter.ToUInt32(data, 0);
                pktID = BitConverter.ToUInt16(data, 8);
                checksum = BitConverter.ToUInt16(data, 10);
                datalen = BitConverter.ToUInt32(data, 12);
                pktID2 = BitConverter.ToUInt16(data, 16);
            }
            else
            {
                //pingpong
            }
        }
        
        public static UInt16 CalculateChecksum(byte[] buf, int length)
        {
            uint value = 0;
            var header = BitConverter.ToUInt32(buf, 0);

            for (var index = 12; index < length; ++index)
                value += (uint)(buf[index]);

            uint result = (uint)(value - (length + (header << 29 >> 29)));
            return (ushort)(result + (result >> 16));
        }

        public static void Decrypt(byte[] buf, uint index, uint length, byte[] key)
        {
            for (var i = 0; i < length; ++i)
            {
                var a = buf[index + i];
                a ^= 0x0F0;
                var b = (byte)(a & 3);
                a >>= 2;
                b <<= 6;
                b = (byte)(a | b);
                buf[index + i] = (byte)(b ^ key[i % 32]);
            }
        }

        public static void Encrypt(byte[] buf, uint index, uint length, byte[] key)
        {
            for (var i = 0; i < length; ++i)
            {
                ushort a = buf[index + i];
                a ^= key[i % 32];
                a <<= 2;

                var b = (byte)(a >> 8);
                b |= (byte)(a & 0xFF);
                b ^= 0xF0;
                buf[index + i] = b;
            }
        }
    }
}
