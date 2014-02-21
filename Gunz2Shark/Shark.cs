using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;
using SharpPcap.WinPcap;
using PacketDotNet;

namespace Gunz2Shark
{
    class Shark
    {
        private List<Command> _commands;
        private WinPcapDevice _device;
        private byte[] _cryptKey = new byte[32];

        public Shark(WinPcapDevice device)
        {
            _commands = new List<Command>();
            _device = device;

            var reader = new StreamReader("proto.json");
            var jss = new JavaScriptSerializer();
            _commands = jss.Deserialize<List<Command>>(reader.ReadToEnd());

            Console.WriteLine("Loaded: {0} commands.", _commands.Count);
        }

        public void Start()
        {
            _device.Open(OpenFlags.Promiscuous, 500);
            _device.Filter = "tcp port 20100";
            _device.OnPacketArrival += OnPacketArrival;
            _device.StartCapture();
        }

        private void OnPacketArrival(object sender, SharpPcap.CaptureEventArgs e)
        {
            var rawPacket = e.Packet;
            var etherPacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var tcpPacket = (TcpPacket)etherPacket.PayloadPacket.PayloadPacket;
            var payload = etherPacket.PayloadPacket.PayloadPacket.PayloadData;
            var toServer = tcpPacket.DestinationPort == 20100;

            if (payload.Length < 1 || payload.Length < 18)
                return;

            var packet = new byte[payload.Length];
            Array.Copy(payload, packet, payload.Length);

            // header size = 12
            var temp = BitConverter.ToUInt32(packet, 0);
            var size = (uint)(0x7FFFFF & (temp >> 5));
            var encrypted = (byte)((temp >> 3) & 1) == 1;
            var compressed = (byte)((temp >> 4) & 1) == 1;

            if (size != packet.Length)
                return;

            // how to check if it it's encrypted.
            if (encrypted)
                Decrypt(packet, 12, (int)packet.Length - 12, _cryptKey);

            var dataSize = BitConverter.ToUInt16(packet, 12);
            var commandId = BitConverter.ToUInt16(packet, 16);

            if (commandId == 0xC1C)
            {
                var index = 33;
                var cryptKeySeed = BitConverter.ToUInt32(packet, index);

                MakeCryptKey(cryptKeySeed);
            }

            var cmd = _commands.Find(x => x.GetOpcode() == commandId);

            if (cmd != null)
            {
                var output = string.Format("[{0}] | {1} | {2}({2:X}) | Parameters ->", toServer ? "C2S" : "S2C", cmd.Desc, cmd.GetOpcode());

                foreach (var param in cmd.Params)
                    output += string.Format("[{0}]|{1} -> ", param.Name.Length > 0 ? param.Name : "Undefined", param.Type);
                
                output += "end";

                Console.WriteLine(output);
            }
            else
                Console.WriteLine("Unknown command: {0}", commandId);
        }

        private void Decrypt(byte[] buf, int index, int length, byte[] key)
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

        private void MakeCryptKey(uint num)
        {
            byte[] XOR = new byte[] { 	
                0x57, 0x02, 0x5B, 0x04, 0x34, 0x06, 0x01,
		        0x08, 0x37, 0x0A, 0x12, 0x69, 0x41, 0x38,
		        0x0F, 0x78 
            };

            byte[] IV = new byte[] { 27, 4, 36, 34, 67, 1, 73, 83, 80, 5, 19, 53, 79, 2, 77, 5 };

            Buffer.BlockCopy(BitConverter.GetBytes(num), 0, _cryptKey, 4, 4);

            for (int i = 0; i < 4; ++i)
            {
                uint a = BitConverter.ToUInt32(XOR, i * 4);
                uint b = BitConverter.ToUInt32(_cryptKey, i * 4);
                Buffer.BlockCopy(BitConverter.GetBytes(a ^ b), 0, _cryptKey, i * 4, 4);
            }

            Buffer.BlockCopy(IV, 0, _cryptKey, 16, 16);
        }

    }
}
