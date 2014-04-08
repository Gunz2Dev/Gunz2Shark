using System;
using System.Collections.Generic;
using System.IO;
using SharpPcap.WinPcap;
using PacketDotNet;

namespace Gunz2Shark
{
    class Program
    {
        static byte[] CryptKey = new byte[32];
        static void Main(string[] args)
        {
            Console.BufferWidth = Console.WindowWidth = 200;
            Console.Title = "GunZ2 Shark";

            WinPcapDevice device = null;
            var devices = WinPcapDeviceList.Instance;
            
            for (var i = 0; i < devices.Count; ++i)
                Console.WriteLine("{0}. {1}", i, devices[i].Description);

            if(args.Length < 1)
                device = devices[2];
            else
                device = devices[Int32.Parse(args[0])];

            var shark = new SharkStream(device);
            shark.Start();

        }

        public static void PacketLog(byte[] data, int index, int length, StreamWriter writer)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            var sDump = (length > 0 ? BitConverter.ToString(data, index, length) : "");
            var sDumpHex = sDump.Split('-');
            var lstDump = new List<string>();
            string sHex = "";
            string sAscii = "";
            char cByte;
            if (sDump.Length > 0)
            {
                for (Int32 iCount = 0; iCount < sDumpHex.Length; iCount++)
                {
                    cByte = Convert.ToChar(data[index + iCount]);
                    sHex += sDumpHex[iCount] + ' ';
                    if (char.IsWhiteSpace(cByte) || char.IsControl(cByte))
                    {
                        cByte = '.';
                    }
                    if (cByte == '{' || cByte == '}')
                        cByte = '.';
                    sAscii += cByte.ToString();
                    if ((iCount + 1) % 16 == 0)
                    {
                        lstDump.Add(sHex + " " + sAscii);
                        sHex = "";
                        sAscii = "";
                    }
                }
                if (sHex.Length > 0)
                {
                    if (sHex.Length < (16 * 3)) sHex += new string(' ', (16 * 3) - sHex.Length);
                    lstDump.Add(sHex + " " + sAscii);
                }
            }
            for (Int32 iCount = 0, j = 0; iCount < lstDump.Count; iCount++, j++)
            {
                writer.WriteLine(lstDump[iCount]);
                Console.WriteLine(lstDump[iCount]);
                writer.Flush();
            }
        }
    }
}
