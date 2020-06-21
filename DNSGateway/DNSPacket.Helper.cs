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
                DoGetFullName(sb, null);
                return sb.ToString();
            }

            protected void DoGetFullName(StringBuilder sb, List<ushort> pl)
            { 
                foreach(Label label in Name)
                {
                    if (label.IsPointer)
                    {
                        ushort nPos = (ushort)(label.Pointer.Value + ((label.Length - 192) << 8));
                        // nPos must be large than 0x09, less than size of the root data
                        if (nPos >= 0x0C && nPos < m_root.m_io.Size)
                        {
                            if (null == pl)
                            {
                                pl = new List<ushort>();
                            }
                            // nPos can not be the same of previous one, to avoid cycle
                            bool bHasCycle = false;
                            foreach(ushort p in pl)
                            {
                                if (p == nPos)
                                {
                                    bHasCycle = true;
                                    break;
                                }
                            }
                            if (!bHasCycle)
                            {
                                pl.Add(nPos);
                                label.Pointer.Contents.DoGetFullName(sb, pl);
                            }
                            else
                            {
                                throw new ArgumentOutOfRangeException("cycle label position " + nPos + " detected");
                            }
                        }
                        else
                        {
                            throw new ArgumentOutOfRangeException("requested position " + nPos + " is out of range");
                        }
                    }
                    else
                    {
                        if (sb.Length > 0)
                        {
                            sb.Append('.');
                        }

                        sb.Append(label.Name);
                    }
                }

                return;
            }
        }
    }
}
