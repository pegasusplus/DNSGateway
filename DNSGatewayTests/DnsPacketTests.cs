using Microsoft.VisualStudio.TestTools.UnitTesting;
using Kaitai;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using PacketDotNet;
using SharpPcapHelper;
using static Kaitai.DnsPacket;
using System.Net;

namespace Kaitai.Tests
{
    [TestClass()]
    public class DnsPacketTests
    {
        private const string StrQueryDomainName = "china.tomorrow.com";
        UdpPacket[] udpPackets;

        [TestInitialize]
        public void ReadDNSPacketsFromPcapFile()
        {
            udpPackets = new UdpPacket[4];
            ushort nPacket = 0;

            // Read first dns packets
            PacketFileManipulator pfm = new PacketFileManipulator(@"..\..\..\Packet\local.dns.192.168.0.219.pcap");
            while (pfm.HasPacket && nPacket < udpPackets.Length)
            {
                Packet packet = pfm.RemoveCurrentPacket();
                UdpPacket udpPacket = (UdpPacket)packet.Extract(typeof(UdpPacket));
                if (null != udpPacket)
                {
                    // Should unpack GRPS
                    udpPackets[nPacket++] = udpPacket;
                }
            }

            Assert.IsTrue(udpPackets.Length == nPacket);
        }

        [TestMethod()]
        public void ParseRequest()
        {
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[0].PayloadData));

            Assert.IsTrue(dnsPacket.TransactionId == 0xf478);
            Assert.IsTrue(0x0100 == dnsPacket.Flags.Flag);
            Assert.IsTrue(1 == dnsPacket.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Arcount);
            Assert.IsTrue(0 == dnsPacket.Ancount);
            Assert.IsTrue(0 == dnsPacket.Nscount);
            Assert.IsTrue(1 == dnsPacket.Queries.Count);
            DnsPacket.Query q = dnsPacket.Queries[0];
            Assert.IsTrue(DnsPacket.TypeType.A == q.Type);
            Assert.IsTrue(DnsPacket.ClassType.InClass == q.QueryClass);
            VerifyName(q.Name.Name, StrQueryDomainName);

            return;
        }

        [TestMethod()]
        public void ParseResponseFrom114()
        {
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[2].PayloadData));

            const string StrAddressExpected = "69.162.80.55";
            const int N_TTL_Expected = 600;

            VerifyAnswer(dnsPacket, StrAddressExpected, N_TTL_Expected);

            return;
        }

        [TestMethod()]
        public void ParseResponseFrom8()
        {
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[3].PayloadData));

            const string StrAddressExpected = "95.211.219.67";
            const int N_TTL_Expected = 599;

            VerifyAnswer(dnsPacket, StrAddressExpected, N_TTL_Expected);

            return;
        }


        private static void VerifyAnswer(DnsPacket dnsPacket, string StrAddressExpected, int ttl)
        {
            Assert.IsTrue(dnsPacket.TransactionId == 0xf478);
            Assert.IsTrue(0x8180 == dnsPacket.Flags.Flag);
            Assert.IsTrue(1 == dnsPacket.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Arcount);
            Assert.IsTrue(1 == dnsPacket.Ancount);
            Assert.IsTrue(0 == dnsPacket.Nscount);
            Assert.IsTrue(1 == dnsPacket.Queries.Count);
            Assert.IsTrue(1 == dnsPacket.Answers.Count);
            DnsPacket.Query q = dnsPacket.Queries[0];
            Assert.IsTrue(DnsPacket.TypeType.A == q.Type);
            Assert.IsTrue(DnsPacket.ClassType.InClass == q.QueryClass);
            VerifyName(q.Name.Name, StrQueryDomainName);

            DnsPacket.Answer a = dnsPacket.Answers[0];
            Assert.IsTrue(DnsPacket.ClassType.InClass == a.AnswerClass);
            Assert.IsTrue(ttl == a.Ttl);
            Assert.IsTrue(DnsPacket.TypeType.A == a.Type);
            VerifyRefName(a.Name.Name);

            VerifyPayloadAddress(a, StrAddressExpected);
        }

        private static void VerifyPayloadAddress(Answer a, string strAddressExpected)
        {
            Assert.IsTrue(4 == a.Rdlength);
            Assert.IsTrue(a.Payload is Address);
            Address aa = (Address)a.Payload;

            IPAddress ip = IPAddress.Parse(strAddressExpected);
            byte[] ipBytes = ip.GetAddressBytes();
            Assert.IsTrue(ipBytes.Length == aa.Ip.Count);
            for(byte n = 0; n<ipBytes.Length; n++)
            {
                Assert.IsTrue(ipBytes[n] == aa.Ip[n], "Address not expected as " + strAddressExpected);
            }
        }

        private static void VerifyName(List<DnsPacket.Label> name, string strExpectedName)
        {
            string[] strsName = strExpectedName.Split('.');

            Assert.IsTrue(strsName.Length + 1 == name.Count);
            for (byte n = 0; n < strsName.Length; n++)
            {
                Assert.AreEqual(strsName[n], name[n].Name);
            }
        }
        private static void VerifyRefName(List<DnsPacket.Label> name)
        {
            Assert.AreEqual((int)1, name.Count);
            Label l = name[0];
            Assert.IsTrue(l.IsPointer);
            Assert.IsTrue(0xC0 == l.Length);
            Assert.IsTrue(0x0C == l.Pointer.Value);

            PointerStruct ps = l.Pointer;
            VerifyName(ps.Contents.Name, StrQueryDomainName);
        }
    }
}