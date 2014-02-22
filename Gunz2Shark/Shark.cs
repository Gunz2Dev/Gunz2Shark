using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
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
        private ushort _srcPort; // we can use this for sending so it goes back to the GunZ2 socket.
        private IPAddress _srcIP;
        private IPAddress _destIP;
        private PhysicalAddress _srcPhsyical;
        private PhysicalAddress _destPhysical;

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

        private bool put = false;
        private void OnPacketArrival(object sender, SharpPcap.CaptureEventArgs e)
        {
            var rawPacket = e.Packet;
            var etherPacket = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ipPacket = (IpPacket)etherPacket.PayloadPacket;
            var tcpPacket = (TcpPacket)etherPacket.PayloadPacket.PayloadPacket;
            var payload = etherPacket.PayloadPacket.PayloadPacket.PayloadData;
            var toServer = tcpPacket.DestinationPort == 20100;

            if (payload.Length < 1 || payload.Length < 18)
                return;

            if (toServer && _srcPort == 0)
            {
                _srcPort = tcpPacket.SourcePort;
                _srcIP = ipPacket.SourceAddress;
                _destIP = ipPacket.DestinationAddress;
                var ether = (EthernetPacket)etherPacket;

                _destPhysical = ether.DestinationHwAddress;
                _srcPhsyical = ether.SourceHwAddress;
            }

            if (toServer && !put)
            {
                put = true;
                Console.WriteLine(etherPacket);
            }

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
            {
                var oldChecksum = BitConverter.ToUInt16(packet, 10);
                Decrypt(packet, 12, (int)packet.Length - 12, _cryptKey);
                Encrypt(packet, 12, (int)packet.Length - 12, _cryptKey);
                var newChecksum = BitConverter.ToUInt16(packet, 10);
                Decrypt(packet, 12, (int)packet.Length - 12, _cryptKey);

                if (newChecksum != oldChecksum)
                    Console.WriteLine("Checksums do not match: {0:X} {1:X}", oldChecksum, newChecksum);
            }

            var dataSize = BitConverter.ToUInt16(packet, 12);
            var commandId = BitConverter.ToUInt16(packet, 16);

            if (commandId == 0xC1C)
            {
                var index = 33;
                var cryptKeySeed = BitConverter.ToUInt32(packet, index);

                MakeCryptKey(cryptKeySeed);
                var writer = new StreamWriter("gunz2shark.log", true);
                writer.WriteLine("[KEY]");
                Program.PacketLog(_cryptKey, 0, _cryptKey.Length, writer);
                writer.WriteLine("[END KEY]\n");
                writer.Close();
            }

            var cmd = _commands.Find(x => x.GetOpcode() == commandId);

            if (cmd != null)
            {
                var writer = new StreamWriter("gunz2shark.log", true);

                var output = string.Format("[{0}] | {1} | {2}({2:X}) | Parameters ->", toServer ? "C2S" : "S2C", cmd.Desc, cmd.GetOpcode());

                foreach (var param in cmd.Params)
                    output += string.Format("[{0}]|{1} -> ", param.Name.Length > 0 ? param.Name : "Undefined", param.Type);

                output += "end";

                Console.WriteLine(output);
                writer.WriteLine(output);
                Program.PacketLog(packet, 0, packet.Length, writer);
                writer.Close();
            }
            else
                Console.WriteLine("Unknown command: {0}", commandId);
        }

        public void SendSupplyBoxOpen()
        {
            byte[] packet = new byte[]
            { 
                0x69, 0x02, 0x00, 0x00, // flags
                0xBB, 0x00, // packet counter.
                0x00, 0x00, // unknown
                0x18, 0x06, // unknown
                0x64, 0x05, // checksum
                0x07, 0x00, // data size
                0x00, 0x00, // unknown
                0x18, 0x06, // command id
                0x00 // data?
            };

            packet[4] = (byte)((int)(packet[4] + 10));
            Encrypt(packet, 12, packet.Length - 12, _cryptKey);

            var checksum = CalculateChecksum(packet, packet.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(checksum), 0, packet, 10, 2);

            var tcp = new TcpPacket(_srcPort, 20100);
            var ip = new IPv4Packet(_srcIP, _destIP);
            var ether = new EthernetPacket(_srcPhsyical, _destPhysical, EthernetPacketType.None);

            tcp.Ack = true;
            tcp.Psh = true;
            tcp.PayloadData = packet;
            ip.PayloadPacket = tcp;
            ether.PayloadPacket = ip;

            Console.WriteLine(ether);
            _device.SendPacket(ether);
        }

        public static UInt16 CalculateChecksum(byte[] buf, int length)
        {
            uint value = 0;
            var header = BitConverter.ToUInt32(buf, 0);

            for (var index = 12; index < length; ++index)
                value += (uint)(buf[index]);

            uint result = (uint)(value - (length + (value << 29 >> 29)));
            return (ushort)(result + (result >> 16));
        }

        public static void Decrypt(byte[] buf, int index, int length, byte[] key)
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

        public static void Encrypt(byte[] buf, int index, int length, byte[] key)
        {
            for(var i = 0; i < length; ++i)
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
