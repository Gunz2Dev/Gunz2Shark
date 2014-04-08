using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Web.Script.Serialization;
using SharpPcap.WinPcap;
using PacketDotNet;
using Ionic.Zlib;

namespace Gunz2Shark
{
    class SharkStream
    {
        private List<Command> _commands;
        private WinPcapDevice _device;
        private byte[] _cryptKey = new byte[32];
        private ushort _srcPort; // we can use this for sending so it goes back to the GunZ2 socket.
        private IPAddress _srcIP;
        private IPAddress _destIP;
        private PhysicalAddress _srcPhsyical;
        private PhysicalAddress _destPhysical;

        public SharkStream(WinPcapDevice device)
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

            if (payload.Length < 1)
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
            Gunz2Packet packet = new Gunz2Packet(payload, _cryptKey);
            if (packet.pktID == 0xC1C)
            {
                Array.Clear(_cryptKey, 0, _cryptKey.Length);
                var index = 33;
                var cryptKeySeed = BitConverter.ToUInt32(packet.data, index);

                MakeCryptKey(cryptKeySeed);
                var writer = new StreamWriter("gunz2shark.log", true);
                writer.WriteLine("[KEY]");
                Program.PacketLog(_cryptKey, 0, _cryptKey.Length, writer);
                writer.WriteLine("[END KEY]\n");
                writer.Close();
            }

            if (packet.pktID == 0xDFC)
            {
                SendSupplyBoxOpen();
            }

            var cmd = _commands.Find(x => x.GetOpcode() == packet.pktID);

            if (cmd != null && !packet.flags.unkFlag3)
            {

                File.WriteAllBytes(cmd.GetOpcode() + ".bin", packet.data);
                var writer = new StreamWriter("gunz2shark.log", true);

                var output = string.Format("[{0}] | {1} | {2}({2:X}) | Parameters ->", toServer ? "C2S" : "S2C", cmd.Desc, cmd.GetOpcode());

                if (cmd.Params != null)
                {
                    foreach (var param in cmd.Params)
                        output += string.Format("{0} -> ", param.Type);
                }

                output += "end";

                Console.WriteLine(output);
                writer.WriteLine(output);
                
                Program.PacketLog(packet.data, 0, (int)packet.data.Length, writer);
                writer.Close();
            }
            else
                Console.WriteLine("Unknown command: {0}", packet.pktID);

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

        public void SendSupplyBoxOpen()
        {
            byte[] packet = new byte[]
            { 
               0x69, 0x04, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xEC, 0x04, 0x8B, 0x11, 0x17, 0x00, 0x00, 0x00,
0xEC, 0x04, 0x00, 0x1F, 0xF7, 0x51, 0x8D, 0x0A, 0x00, 0x61, 0x00, 0x73, 0x00, 0x64, 0x00, 0x66,
0x00, 0x00, 0x00
            };

            packet[4] = (byte)((int)(packet[4] + 10));
            Gunz2Packet.Encrypt(packet, 12, (uint)packet.Length - 12, _cryptKey);

            var checksum = Gunz2Packet.CalculateChecksum(packet, packet.Length);
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

    }
}
