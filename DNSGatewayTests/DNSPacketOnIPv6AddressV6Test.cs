﻿using Kaitai;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using SharpPcapHelper;
using System.Collections.Generic;
using System.Net;
using static Kaitai.DnsPacket;

namespace Kaitai.Tests
{
    [TestClass()]
    public class DNSPacketOnIPv6AddressV6Test
    {
        private const string StrQueryDomainName = "live.github.com";
        UdpPacket[] udpPackets;

        [TestInitialize]
        public void ReadDNSPacketsFromPcapFile()
        {
            udpPackets = new UdpPacket[6];
            ushort nPacket = 0;

            // Read first dns packets
            PacketFileManipulator pfm = new PacketFileManipulator(@"..\..\..\Packet\local.dns.github.facebook.v6onv6.pcap");
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
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[1].PayloadData));

            Assert.AreEqual(dnsPacket.TransactionId, (ushort)0x1622);
            //Assert.AreEqual((ushort)0x0100, dnsPacket.Flags.Flag);
            Assert.IsTrue(dnsPacket.Flags.IsOpcodeValid);
            Assert.IsTrue(dnsPacket.Flags.Rd);
            Assert.AreEqual((ushort)1, dnsPacket.Body.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Body.Arcount);
            Assert.IsTrue(0 == dnsPacket.Body.Ancount);
            Assert.IsTrue(0 == dnsPacket.Body.Nscount);
            Assert.AreEqual((ushort)1, dnsPacket.Body.Queries.Count);
            DnsPacket.Query q = dnsPacket.Body.Queries[0];
            Assert.AreEqual(DnsPacket.TypeType.Aaaa, q.Type);
            Assert.AreEqual(DnsPacket.ClassType.InClass, q.QueryClass);
            Assert.AreEqual(q.Name.GetFullName(), StrQueryDomainName);

            return;
        }

        [TestMethod()]
        public void ParseResponseFrom114()
        {
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[3].PayloadData));

            const string StrAddressExpected = "2001::1f0d:4c10";
            const int N_TTL_Expected = 89;

            VerifyAnswer(dnsPacket, StrAddressExpected, N_TTL_Expected);

            return;
        }

        private static void VerifyAnswer(DnsPacket dnsPacket, string StrAddressExpected, int ttl)
        {
            Assert.AreEqual(dnsPacket.TransactionId, (ushort)0x1622);
            //Assert.AreEqual((ushort)0x8180, dnsPacket.Flags.Flag);
            Assert.IsTrue(dnsPacket.Flags.IsOpcodeValid);
            Assert.IsTrue(dnsPacket.Flags.Rd);
            Assert.IsTrue(dnsPacket.Flags.Qr);
            Assert.IsTrue(dnsPacket.Flags.Ra);
            Assert.IsTrue(1 == dnsPacket.Body.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Body.Ancount);
            Assert.IsTrue(0 == dnsPacket.Body.Arcount);
            Assert.IsTrue(0 == dnsPacket.Body.Nscount);
            Assert.IsTrue(1 == dnsPacket.Body.Queries.Count);
            Assert.IsTrue(null == dnsPacket.Body.Answers);
            DnsPacket.Query q = dnsPacket.Body.Queries[0];
            Assert.AreEqual(DnsPacket.TypeType.Aaaa, q.Type);
            Assert.AreEqual(DnsPacket.ClassType.InClass, q.QueryClass);
            Assert.AreEqual(q.Name.GetFullName(), StrQueryDomainName);

            //DnsPacket.Answer a = dnsPacket.Body.Answers[0];
            //Assert.IsTrue(DnsPacket.ClassType.InClass == a.AnswerClass);
            //Assert.IsTrue(ttl == a.Ttl);
            //Assert.IsTrue(DnsPacket.TypeType.Aaaa == a.Type);
            //Assert.AreEqual(a.Name.GetFullName(), StrQueryDomainName);

            //VerifyPayloadAddressV6(a, StrAddressExpected);
        }

        private static void VerifyPayloadAddressV6(Answer a, string strAddressExpected)
        {
            Assert.AreEqual(16, a.Rdlength);
            Assert.IsTrue(a.Payload is AddressV6);
            AddressV6 aa = (AddressV6)a.Payload;

            IPAddress ip = IPAddress.Parse(strAddressExpected);
            byte[] ipBytes = ip.GetAddressBytes();
            Assert.IsTrue(ipBytes.Length == aa.IpV6.Length);
            for (byte n = 0; n < ipBytes.Length; n++)
            {
                Assert.IsTrue(ipBytes[n] == aa.IpV6[n], "Address not expected as " + strAddressExpected);
            }
        }

        private static void VerifyName(List<DnsPacket.Label> name, string strExpectedName)
        {
            string[] strsName = strExpectedName.Split('.');

            //Assert.IsTrue(strsName.Length + 1 == name.Count);
            Assert.AreEqual(strsName.Length, name.Count);
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
