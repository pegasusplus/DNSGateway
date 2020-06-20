using Kaitai;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PacketDotNet;
using SharpPcapHelper;
using System.Collections.Generic;
using System.Net;
using static Kaitai.DnsPacket;

namespace Kaitai.Tests
{
    [TestClass()]
    public class DNSPacketAddressV6Test
    {
        private const string StrQueryDomainName = "www.github.com";
        UdpPacket[] udpPackets;

        [TestInitialize]
        public void ReadDNSPacketsFromPcapFile()
        {
            udpPackets = new UdpPacket[6];
            ushort nPacket = 0;

            // Read first dns packets
            PacketFileManipulator pfm = new PacketFileManipulator(@"..\..\..\Packet\local.dns.github.facebook.v6onv4.pcap");
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
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[2].PayloadData));

            Assert.IsTrue(dnsPacket.TransactionId == 0x0006);
            Assert.IsTrue(0x0100 == dnsPacket.Flags.Flag);
            Assert.IsTrue(1 == dnsPacket.Body.Qdcount);
            Assert.IsTrue(0 == dnsPacket.Body.Arcount);
            Assert.IsTrue(0 == dnsPacket.Body.Ancount);
            Assert.IsTrue(0 == dnsPacket.Body.Nscount);
            Assert.IsTrue(1 == dnsPacket.Body.Queries.Count);
            DnsPacket.Query q = dnsPacket.Body.Queries[0];
            Assert.IsTrue(DnsPacket.TypeType.Aaaa == q.Type);
            Assert.IsTrue(DnsPacket.ClassType.InClass == q.QueryClass);
            VerifyName(q.Name.Name, StrQueryDomainName);

            return;
        }

        [TestMethod()]
        public void ParseResponseFrom114()
        {
            DnsPacket dnsPacket = new DnsPacket(new KaitaiStream(udpPackets[3].PayloadData));

            const string StrAddressExpected = "2001::1f0d:4c10";
            const int N_TTL_Expected = 2296;

            VerifyAnswer(dnsPacket, StrAddressExpected, N_TTL_Expected);

            return;
        }

        private static void VerifyAnswer(DnsPacket dnsPacket, string StrAddressExpected, int ttl)
        {
            Assert.AreEqual(dnsPacket.TransactionId, (ushort)0x0006);
            Assert.AreEqual((ushort)0x8180, dnsPacket.Flags.Flag);
            Assert.AreEqual((ushort)1, dnsPacket.Body.Qdcount);
            Assert.AreEqual((ushort)1, dnsPacket.Body.Ancount);
            Assert.AreEqual(1, dnsPacket.Body.Nscount);
            Assert.AreEqual(0, dnsPacket.Body.Arcount);
            Assert.IsTrue(1 == dnsPacket.Body.Queries.Count);
            Assert.IsTrue(1 == dnsPacket.Body.Answers.Count);
            Assert.IsTrue(1 == dnsPacket.Body.Authorities.Count);
            DnsPacket.Query q = dnsPacket.Body.Queries[0];
            Assert.IsTrue(DnsPacket.TypeType.Aaaa == q.Type);
            Assert.IsTrue(DnsPacket.ClassType.InClass == q.QueryClass);
            VerifyName(q.Name.Name, StrQueryDomainName);

            DnsPacket.Answer a = dnsPacket.Body.Answers[0];
            Assert.AreEqual(DnsPacket.ClassType.InClass, a.AnswerClass);
            Assert.AreEqual(ttl, a.Ttl);
            Assert.AreEqual(DnsPacket.TypeType.Cname, a.Type);

            VerifyRefName(a.Name.Name);

            DnsPacket.Answer ns = dnsPacket.Body.Authorities[0];
            Assert.AreEqual(DnsPacket.ClassType.InClass, ns.AnswerClass);
            Assert.AreEqual(37, ns.Ttl);
            Assert.AreEqual(DnsPacket.TypeType.Soa, ns.Type);
            Assert.AreEqual(53, ns.Rdlength);
            Assert.AreEqual(ns.Payload.GetType(), typeof(DnsPacket.AuthorityInfo));
            Assert.AreEqual(ns.Name.GetFullName(), "github.com");

            DnsPacket.AuthorityInfo nsInfo = (DnsPacket.AuthorityInfo)ns.Payload;
            Assert.AreEqual(nsInfo.ExpireLimit, (uint)604800);
            Assert.AreEqual(nsInfo.MinTtl, (uint)60);
            Assert.AreEqual(nsInfo.Serial, (uint)1592319081);
            Assert.AreEqual(nsInfo.RetryInterval, (uint)600);
            Assert.AreEqual(nsInfo.RefreshInterval, (uint)3600);
            VerifyName(nsInfo.PrimaryNs.Name, "ns1.p16.dynect.net");
            Assert.AreEqual(nsInfo.ResoponsibleMailbox.GetFullName(), "hostmaster.github.com");
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
