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
                //DoGetFullName(sb, null);
                DoGetFullName(sb, 0);
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
                            // if pointer to pos is after current, it might be a cycle
                            // how to know current label start pos?
                            if (null == pl)
                            {
                                pl = new List<ushort>();
                            }
                            // nPos can not be the same of previous one, to avoid cycle
                            // nPos must be less than previous one - 2
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
                                break; // Do not support pointer after pointer. Only last label can be pointer
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
            protected void DoGetFullName(StringBuilder sb, ushort nPreviousPos)
            {
                foreach (Label label in Name)
                {
                    if (label.IsPointer)
                    {
                        ushort nPos = (ushort)(label.Pointer.Value + ((label.Length - 192) << 8));
                        // nPos must be large than 0x09, less than size of the root data
                        if (nPos >= 0x0C && nPos < m_root.m_io.Size && (0 == nPreviousPos || nPos < nPreviousPos - 1))
                        {
                            // nPos must be less than previous pos - 1
                            label.Pointer.Contents.DoGetFullName(sb, nPos);
                            break; // Do not support pointer after pointer. Only last label can be pointer
                        }
                        else
                        {
                            throw new ArgumentOutOfRangeException("requested position " + nPos + " is out of range or cause cycle");
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
