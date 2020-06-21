// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

using System.Collections.Generic;

namespace Kaitai
{

    /// <summary>
    /// (No support for Auth-Name + Add-Name for simplicity)
    /// </summary>
    public partial class DnsPacket : KaitaiStruct
    {
        public static DnsPacket FromFile(string fileName)
        {
            return new DnsPacket(new KaitaiStream(fileName));
        }


        public enum ClassType
        {
            InClass = 1,
            Cs = 2,
            Ch = 3,
            Hs = 4,
        }

        public enum TypeType
        {
            A = 1,
            Ns = 2,
            Md = 3,
            Mf = 4,
            Cname = 5,
            Soa = 6,
            Mb = 7,
            Mg = 8,
            Mr = 9,
            Null = 10,
            Wks = 11,
            Ptr = 12,
            Hinfo = 13,
            Minfo = 14,
            Mx = 15,
            Txt = 16,
            Aaaa = 28,
            Srv = 33,
        }
        public DnsPacket(KaitaiStream p__io, KaitaiStruct p__parent = null, DnsPacket p__root = null) : base(p__io)
        {
            m_parent = p__parent;
            m_root = p__root ?? this;
            _read();
        }
        private void _read()
        {
            _transactionId = m_io.ReadU2be();
            _flags = new PacketFlags(m_io, this, m_root);
            if (Flags.IsOpcodeValid) {
                _body = new MessageBody(m_io, this, m_root);
            }
        }
        public partial class MxInfo : KaitaiStruct
        {
            public static MxInfo FromFile(string fileName)
            {
                return new MxInfo(new KaitaiStream(fileName));
            }

            public MxInfo(KaitaiStream p__io, DnsPacket.Answer p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _preference = m_io.ReadU2be();
                _mx = new DomainName(m_io, this, m_root);
            }
            private ushort _preference;
            private DomainName _mx;
            private DnsPacket m_root;
            private DnsPacket.Answer m_parent;
            public ushort Preference { get { return _preference; } }
            public DomainName Mx { get { return _mx; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Answer M_Parent { get { return m_parent; } }
        }
        public partial class PointerStruct : KaitaiStruct
        {
            public static PointerStruct FromFile(string fileName)
            {
                return new PointerStruct(new KaitaiStream(fileName));
            }

            public PointerStruct(KaitaiStream p__io, DnsPacket.Label p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                f_contents = false;
                _read();
            }
            private void _read()
            {
                _value = m_io.ReadU1();
            }
            private bool f_contents;
            private DomainName _contents;
            public DomainName Contents
            {
                get
                {
                    if (f_contents)
                        return _contents;
                    KaitaiStream io = M_Root.M_Io;
                    long _pos = io.Pos;
                    io.Seek((Value + ((M_Parent.Length - 192) << 8)));
                    _contents = new DomainName(io, this, m_root);
                    io.Seek(_pos);
                    f_contents = true;
                    return _contents;
                }
            }
            private byte _value;
            private DnsPacket m_root;
            private DnsPacket.Label m_parent;

            /// <summary>
            /// Read one byte, then offset to that position, read one domain-name and return
            /// </summary>
            public byte Value { get { return _value; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Label M_Parent { get { return m_parent; } }
        }
        public partial class Label : KaitaiStruct
        {
            public static Label FromFile(string fileName)
            {
                return new Label(new KaitaiStream(fileName));
            }

            public Label(KaitaiStream p__io, DnsPacket.DomainName p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                f_isPointer = false;
                _read();
            }
            private void _read()
            {
                _length = m_io.ReadU1();
                if (IsPointer) {
                    _pointer = new PointerStruct(m_io, this, m_root);
                }
                if (!(IsPointer)) {
                    _name = System.Text.Encoding.GetEncoding("utf-8").GetString(m_io.ReadBytes(Length));
                }
            }
            private bool f_isPointer;
            private bool _isPointer;
            public bool IsPointer
            {
                get
                {
                    if (f_isPointer)
                        return _isPointer;
                    _isPointer = (bool) (Length >= 192);
                    f_isPointer = true;
                    return _isPointer;
                }
            }
            private byte _length;
            private PointerStruct _pointer;
            private string _name;
            private DnsPacket m_root;
            private DnsPacket.DomainName m_parent;

            /// <summary>
            /// RFC1035 4.1.4: If the first two bits are raised it's a pointer-offset to a previously defined name
            /// </summary>
            public byte Length { get { return _length; } }
            public PointerStruct Pointer { get { return _pointer; } }

            /// <summary>
            /// Otherwise its a string the length of the length value
            /// </summary>
            public string Name { get { return _name; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.DomainName M_Parent { get { return m_parent; } }
        }
        public partial class MessageBody : KaitaiStruct
        {
            public static MessageBody FromFile(string fileName)
            {
                return new MessageBody(new KaitaiStream(fileName));
            }

            public MessageBody(KaitaiStream p__io, DnsPacket p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _qdcount = m_io.ReadU2be();
                _ancount = m_io.ReadU2be();
                _nscount = m_io.ReadU2be();
                _arcount = m_io.ReadU2be();
                if (Qdcount > 0) {
                    _queries = new List<Query>((int) (Qdcount));
                    for (var i = 0; i < Qdcount; i++)
                    {
                        _queries.Add(new Query(m_io, this, m_root));
                    }
                }
                if (Ancount > 0) {
                    _answers = new List<Answer>((int) (Ancount));
                    for (var i = 0; i < Ancount; i++)
                    {
                        _answers.Add(new Answer(m_io, this, m_root));
                    }
                }
                if (Nscount > 0) {
                    _authorities = new List<Answer>((int) (Nscount));
                    for (var i = 0; i < Nscount; i++)
                    {
                        _authorities.Add(new Answer(m_io, this, m_root));
                    }
                }
                if (Arcount > 0) {
                    _additionals = new List<Answer>((int) (Arcount));
                    for (var i = 0; i < Arcount; i++)
                    {
                        _additionals.Add(new Answer(m_io, this, m_root));
                    }
                }
            }
            private ushort _qdcount;
            private ushort _ancount;
            private ushort _nscount;
            private ushort _arcount;
            private List<Query> _queries;
            private List<Answer> _answers;
            private List<Answer> _authorities;
            private List<Answer> _additionals;
            private DnsPacket m_root;
            private DnsPacket m_parent;

            /// <summary>
            /// How many questions are there
            /// </summary>
            public ushort Qdcount { get { return _qdcount; } }

            /// <summary>
            /// Number of resource records answering the question
            /// </summary>
            public ushort Ancount { get { return _ancount; } }

            /// <summary>
            /// Number of resource records pointing toward an authority
            /// </summary>
            public ushort Nscount { get { return _nscount; } }

            /// <summary>
            /// Number of resource records holding additional information
            /// </summary>
            public ushort Arcount { get { return _arcount; } }
            public List<Query> Queries { get { return _queries; } }
            public List<Answer> Answers { get { return _answers; } }
            public List<Answer> Authorities { get { return _authorities; } }
            public List<Answer> Additionals { get { return _additionals; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket M_Parent { get { return m_parent; } }
        }
        public partial class Query : KaitaiStruct
        {
            public static Query FromFile(string fileName)
            {
                return new Query(new KaitaiStream(fileName));
            }

            public Query(KaitaiStream p__io, DnsPacket.MessageBody p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _name = new DomainName(m_io, this, m_root);
                _type = ((DnsPacket.TypeType) m_io.ReadU2be());
                _queryClass = ((DnsPacket.ClassType) m_io.ReadU2be());
            }
            private DomainName _name;
            private TypeType _type;
            private ClassType _queryClass;
            private DnsPacket m_root;
            private DnsPacket.MessageBody m_parent;
            public DomainName Name { get { return _name; } }
            public TypeType Type { get { return _type; } }
            public ClassType QueryClass { get { return _queryClass; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.MessageBody M_Parent { get { return m_parent; } }
        }
        public partial class DomainName : KaitaiStruct
        {
            public static DomainName FromFile(string fileName)
            {
                return new DomainName(new KaitaiStream(fileName));
            }

            public DomainName(KaitaiStream p__io, KaitaiStruct p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _name = new List<Label>();
                {
                    Label M_;
                    do {
                        M_ = new Label(m_io, this, m_root);
                        if (0 == M_.Length)
                        {
                            break;
                        }
                        _name.Add(M_);
                    } while (!(((M_.Length >= 192))));
                }
            }
            private List<Label> _name;
            private DnsPacket m_root;
            private KaitaiStruct m_parent;

            /// <summary>
            /// Repeat until the length is 0 or it is a pointer (bit-hack to get around lack of OR operator)
            /// </summary>
            public List<Label> Name { get { return _name; } }
            public DnsPacket M_Root { get { return m_root; } }
            public KaitaiStruct M_Parent { get { return m_parent; } }
        }
        public partial class AddressV6 : KaitaiStruct
        {
            public static AddressV6 FromFile(string fileName)
            {
                return new AddressV6(new KaitaiStream(fileName));
            }

            public AddressV6(KaitaiStream p__io, DnsPacket.Answer p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _ipV6 = m_io.ReadBytes(16);
            }
            private byte[] _ipV6;
            private DnsPacket m_root;
            private DnsPacket.Answer m_parent;
            public byte[] IpV6 { get { return _ipV6; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Answer M_Parent { get { return m_parent; } }
        }
        public partial class Service : KaitaiStruct
        {
            public static Service FromFile(string fileName)
            {
                return new Service(new KaitaiStream(fileName));
            }

            public Service(KaitaiStream p__io, DnsPacket.Answer p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _priority = m_io.ReadU2be();
                _weight = m_io.ReadU2be();
                _port = m_io.ReadU2be();
                _target = new DomainName(m_io, this, m_root);
            }
            private ushort _priority;
            private ushort _weight;
            private ushort _port;
            private DomainName _target;
            private DnsPacket m_root;
            private DnsPacket.Answer m_parent;
            public ushort Priority { get { return _priority; } }
            public ushort Weight { get { return _weight; } }
            public ushort Port { get { return _port; } }
            public DomainName Target { get { return _target; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Answer M_Parent { get { return m_parent; } }
        }
        public partial class TxtBody : KaitaiStruct
        {
            public static TxtBody FromFile(string fileName)
            {
                return new TxtBody(new KaitaiStream(fileName));
            }

            public TxtBody(KaitaiStream p__io, DnsPacket.Answer p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _length = m_io.ReadU1();
                _text = System.Text.Encoding.GetEncoding("utf-8").GetString(m_io.ReadBytes(Length));
            }
            private byte _length;
            private string _text;
            private DnsPacket m_root;
            private DnsPacket.Answer m_parent;
            public byte Length { get { return _length; } }
            public string Text { get { return _text; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Answer M_Parent { get { return m_parent; } }
        }
        public partial class Address : KaitaiStruct
        {
            public static Address FromFile(string fileName)
            {
                return new Address(new KaitaiStream(fileName));
            }

            public Address(KaitaiStream p__io, DnsPacket.Answer p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _ip = m_io.ReadBytes(4);
            }
            private byte[] _ip;
            private DnsPacket m_root;
            private DnsPacket.Answer m_parent;
            public byte[] Ip { get { return _ip; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Answer M_Parent { get { return m_parent; } }
        }
        public partial class Answer : KaitaiStruct
        {
            public static Answer FromFile(string fileName)
            {
                return new Answer(new KaitaiStream(fileName));
            }

            public Answer(KaitaiStream p__io, DnsPacket.MessageBody p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _name = new DomainName(m_io, this, m_root);
                _type = ((DnsPacket.TypeType) m_io.ReadU2be());
                _answerClass = ((DnsPacket.ClassType) m_io.ReadU2be());
                _ttl = m_io.ReadS4be();
                _rdlength = m_io.ReadU2be();
                switch (Type) {
                case DnsPacket.TypeType.Mx: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new MxInfo(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Ptr: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new DomainName(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Soa: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new AuthorityInfo(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Cname: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new DomainName(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Aaaa: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new AddressV6(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Txt: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new TxtBody(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Ns: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new DomainName(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.Srv: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new Service(io___raw_payload, this, m_root);
                    break;
                }
                case DnsPacket.TypeType.A: {
                    __raw_payload = m_io.ReadBytes(Rdlength);
                    var io___raw_payload = new KaitaiStream(__raw_payload);
                    _payload = new Address(io___raw_payload, this, m_root);
                    break;
                }
                default: {
                    _payload = m_io.ReadBytes(Rdlength);
                    break;
                }
                }
            }
            private DomainName _name;
            private TypeType _type;
            private ClassType _answerClass;
            private int _ttl;
            private ushort _rdlength;
            private object _payload;
            private DnsPacket m_root;
            private DnsPacket.MessageBody m_parent;
            private byte[] __raw_payload;
            public DomainName Name { get { return _name; } }
            public TypeType Type { get { return _type; } }
            public ClassType AnswerClass { get { return _answerClass; } }

            /// <summary>
            /// Time to live (in seconds)
            /// </summary>
            public int Ttl { get { return _ttl; } }

            /// <summary>
            /// Length in octets of the following payload
            /// </summary>
            public ushort Rdlength { get { return _rdlength; } }
            public object Payload { get { return _payload; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.MessageBody M_Parent { get { return m_parent; } }
            public byte[] M_RawPayload { get { return __raw_payload; } }
        }
        public partial class PacketFlags : KaitaiStruct
        {
            public static PacketFlags FromFile(string fileName)
            {
                return new PacketFlags(new KaitaiStream(fileName));
            }

            public PacketFlags(KaitaiStream p__io, DnsPacket p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                f_isOpcodeValid = false;
                _read();
            }
            private void _read()
            {
                _qr = m_io.ReadBitsIntBe(1) != 0;
                _opcode = m_io.ReadBitsIntBe(4);
                _aa = m_io.ReadBitsIntBe(1) != 0;
                _tc = m_io.ReadBitsIntBe(1) != 0;
                _rd = m_io.ReadBitsIntBe(1) != 0;
                _ra = m_io.ReadBitsIntBe(1) != 0;
                _z = m_io.ReadBitsIntBe(1) != 0;
                _ad = m_io.ReadBitsIntBe(1) != 0;
                _cd = m_io.ReadBitsIntBe(1) != 0;
                _rcode = m_io.ReadBitsIntBe(4);
            }
            private bool f_isOpcodeValid;
            private bool _isOpcodeValid;
            public bool IsOpcodeValid
            {
                get
                {
                    if (f_isOpcodeValid)
                        return _isOpcodeValid;
                    _isOpcodeValid = (bool) ( ((Opcode == 0) || (Opcode == 1) || (Opcode == 2)) );
                    f_isOpcodeValid = true;
                    return _isOpcodeValid;
                }
            }
            private bool _qr;
            private ulong _opcode;
            private bool _aa;
            private bool _tc;
            private bool _rd;
            private bool _ra;
            private bool _z;
            private bool _ad;
            private bool _cd;
            private ulong _rcode;
            private DnsPacket m_root;
            private DnsPacket m_parent;
            public bool Qr { get { return _qr; } }
            public ulong Opcode { get { return _opcode; } }
            public bool Aa { get { return _aa; } }
            public bool Tc { get { return _tc; } }
            public bool Rd { get { return _rd; } }
            public bool Ra { get { return _ra; } }
            public bool Z { get { return _z; } }
            public bool Ad { get { return _ad; } }
            public bool Cd { get { return _cd; } }
            public ulong Rcode { get { return _rcode; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket M_Parent { get { return m_parent; } }
        }
        public partial class AuthorityInfo : KaitaiStruct
        {
            public static AuthorityInfo FromFile(string fileName)
            {
                return new AuthorityInfo(new KaitaiStream(fileName));
            }

            public AuthorityInfo(KaitaiStream p__io, DnsPacket.Answer p__parent = null, DnsPacket p__root = null) : base(p__io)
            {
                m_parent = p__parent;
                m_root = p__root;
                _read();
            }
            private void _read()
            {
                _primaryNs = new DomainName(m_io, this, m_root);
                _resoponsibleMailbox = new DomainName(m_io, this, m_root);
                _serial = m_io.ReadU4be();
                _refreshInterval = m_io.ReadU4be();
                _retryInterval = m_io.ReadU4be();
                _expireLimit = m_io.ReadU4be();
                _minTtl = m_io.ReadU4be();
            }
            private DomainName _primaryNs;
            private DomainName _resoponsibleMailbox;
            private uint _serial;
            private uint _refreshInterval;
            private uint _retryInterval;
            private uint _expireLimit;
            private uint _minTtl;
            private DnsPacket m_root;
            private DnsPacket.Answer m_parent;
            public DomainName PrimaryNs { get { return _primaryNs; } }
            public DomainName ResoponsibleMailbox { get { return _resoponsibleMailbox; } }
            public uint Serial { get { return _serial; } }
            public uint RefreshInterval { get { return _refreshInterval; } }
            public uint RetryInterval { get { return _retryInterval; } }
            public uint ExpireLimit { get { return _expireLimit; } }
            public uint MinTtl { get { return _minTtl; } }
            public DnsPacket M_Root { get { return m_root; } }
            public DnsPacket.Answer M_Parent { get { return m_parent; } }
        }
        private ushort _transactionId;
        private PacketFlags _flags;
        private MessageBody _body;
        private DnsPacket m_root;
        private KaitaiStruct m_parent;

        /// <summary>
        /// ID to keep track of request/responces
        /// </summary>
        public ushort TransactionId { get { return _transactionId; } }
        public PacketFlags Flags { get { return _flags; } }
        public MessageBody Body { get { return _body; } }
        public DnsPacket M_Root { get { return m_root; } }
        public KaitaiStruct M_Parent { get { return m_parent; } }
    }
}
