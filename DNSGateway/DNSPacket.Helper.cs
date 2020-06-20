using System;
using System.Collections.Generic;
using System.Text;

namespace Kaitai
{
    public partial class DnsPacket : KaitaiStruct
    {
        public partial class DomainName : KaitaiStruct
        {
            /// <summary>
            /// GetFullName
            /// Try concat labels, verify there's no invalid reference
            /// </summary>
            /// <returns></returns>
            public string GetFullName()
            {
                StringBuilder sb = new StringBuilder();
                foreach(Label label in Name)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append('.');
                    }

                    if (label.IsPointer)
                    {
                        sb.Append(label.Pointer.Contents.GetFullName());
                    }
                    else
                    {
                        sb.Append(label.Name);
                    }
                }
                return sb.ToString();
            }
        }
    }
}
