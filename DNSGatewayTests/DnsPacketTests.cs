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
            Assert.IsTrue(1 == dnsPacket.Body.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Body.Arcount);
            Assert.IsTrue(0 == dnsPacket.Body.Ancount);
            Assert.IsTrue(0 == dnsPacket.Body.Nscount);
            Assert.IsTrue(1 == dnsPacket.Body.Queries.Count);
            DnsPacket.Query q = dnsPacket.Body.Queries[0];
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

        [TestMethod()]
        public void ParseInvalidNameLabel()
        {
            // Modify name segment length to exceed packet data end
            // offset 12, 0x05, -> length of 'china'
            // modify as 24, so that offset + length >= data size, i.e. 36

            byte[] byteData = udpPackets[0].PayloadData;
            Assert.IsTrue(0x05 == byteData[12]);

            byteData[12] = 24;
            try
            {
                DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(byteData));
                Assert.Fail("Invalid packet data passed");
            }
            catch(System.IO.EndOfStreamException)
            {
                Assert.IsTrue(true);
            }

            return;
        }

        [TestMethod()]
        public void ParseInvalidRefNameLength()
        {
            // Modify name segment length to exceed packet data end
            // offset 36, 0xC0, -> pointer, offset 0 << 8 + data[37]
            // offset 37, 0x0C, -> begining of name in header, 'china'
            // modify offset as 24, so that offset + length >= data size, i.e. 36

            byte[] byteData = udpPackets[2].PayloadData;
            Assert.IsTrue(0xC0 == byteData[36]);
            Assert.IsTrue(0x0C == byteData[37]);

            byteData[36] = 0xC1;
            byteData[37] = (byte)byteData.Length;
            //try
            {
                DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(byteData));

                DnsPacket.Query q = dnsPacket.Body.Queries[0];
                VerifyName(q.Name.Name, StrQueryDomainName);

                DnsPacket.Answer a = dnsPacket.Body.Answers[0];
                Assert.IsTrue(DnsPacket.ClassType.InClass == a.AnswerClass);
                Assert.IsTrue(600 == a.Ttl);
                Assert.IsTrue(DnsPacket.TypeType.A == a.Type);
                //VerifyRefName(a.Name.Name);
                {
                    Assert.AreEqual((int)1, a.Name.Name.Count);
                    Label l = a.Name.Name[0];
                    Assert.IsTrue(l.IsPointer);
                    Assert.IsTrue(0xC1 == l.Length);
                    Assert.IsTrue(byteData.Length == l.Pointer.Value);

                    PointerStruct ps = l.Pointer;
                    try
                    {
                        VerifyName(ps.Contents.Name, StrQueryDomainName);
                    }
                    catch(System.IO.EndOfStreamException)
                    {
                        Assert.IsTrue(true);
                    }
                }
            }
            //catch (System.IO.EndOfStreamException)
            {
                Assert.IsTrue(true);
            }

            return;
        }

        [TestMethod()]
        public void ParseLoopRefNameOffset()
        {
            // Modify name segment length to exceed packet data end
            // offset 36, 0xC0, -> pointer, offset 0 << 8 + data[37]
            // offset 37, 0x0C, -> begining of name in header, 'china'
            // modify offset as 24, so that offset + length >= data size, i.e. 36

            byte[] byteData = udpPackets[2].PayloadData;
            Assert.IsTrue(0xC0 == byteData[36]);
            Assert.IsTrue(0x0C == byteData[37]);

            byteData[36] = 0xC0;
            byteData[37] = 36;
            //try
            {
                DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(byteData));

                DnsPacket.Query q = dnsPacket.Body.Queries[0];
                VerifyName(q.Name.Name, StrQueryDomainName);

                DnsPacket.Answer a = dnsPacket.Body.Answers[0];
                Assert.IsTrue(DnsPacket.ClassType.InClass == a.AnswerClass);
                Assert.IsTrue(600 == a.Ttl);
                Assert.IsTrue(DnsPacket.TypeType.A == a.Type);
                //VerifyRefName(a.Name.Name);
                {
                    Assert.AreEqual((int)1, a.Name.Name.Count);
                    Label l = a.Name.Name[0];
                    Assert.IsTrue(l.IsPointer);
                    Assert.IsTrue(0xC0 == l.Length);
                    Assert.IsTrue(36 == l.Pointer.Value);

                    PointerStruct ps = l.Pointer;
                    try
                    {
                        //VerifyName(ps.Contents.Name, StrQueryDomainName);
                        Assert.AreEqual(1, ps.Contents.Name.Count);
                        Label l2 = ps.Contents.Name[0];
                        Assert.AreEqual(true, l2.IsPointer);
                        Assert.AreEqual(0xC0, l2.Length);
                        Assert.AreEqual((byte)36, l2.Pointer.Value);
                    }
                    catch (Exception)
                    {
                        Assert.Fail();
                    }
                }
            }
            //catch (System.IO.EndOfStreamException)
            {
                Assert.IsTrue(true);
            }

            return;
        }

        private static void VerifyAnswer(DnsPacket dnsPacket, string StrAddressExpected, int ttl)
        {
            Assert.IsTrue(dnsPacket.TransactionId == 0xf478);
            Assert.IsTrue(0x8180 == dnsPacket.Flags.Flag);
            Assert.IsTrue(1 == dnsPacket.Body.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Body.Arcount);
            Assert.IsTrue(1 == dnsPacket.Body.Ancount);
            Assert.IsTrue(0 == dnsPacket.Body.Nscount);
            Assert.IsTrue(1 == dnsPacket.Body.Queries.Count);
            Assert.IsTrue(1 == dnsPacket.Body.Answers.Count);
            DnsPacket.Query q = dnsPacket.Body.Queries[0];
            Assert.IsTrue(DnsPacket.TypeType.A == q.Type);
            Assert.IsTrue(DnsPacket.ClassType.InClass == q.QueryClass);
            VerifyName(q.Name.Name, StrQueryDomainName);

            DnsPacket.Answer a = dnsPacket.Body.Answers[0];
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
            Assert.IsTrue(ipBytes.Length == aa.Ip.Length);
            for(byte n = 0; n<ipBytes.Length; n++)
            {
                Assert.IsTrue(ipBytes[n] == aa.Ip[n], "Address not expected as " + strAddressExpected);
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