using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AddressLibraryManager
{
    public partial class OffsetLookupForm : Form
    {
        public OffsetLookupForm()
        {
            InitializeComponent();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            this.UpdateMe(this.textBox1.Text);
        }

        private sealed class VerLookup
        {
            internal Library L;
            internal Dictionary<long, ulong> Reverse = new Dictionary<long, ulong>();
        }

        private readonly List<VerLookup> Versions = new List<VerLookup>();

        public void UpdateMe(string input)
        {
            var bld = new StringBuilder();

            if (this.checkBox1.Checked)
                this.WriteHeader(bld);

            List<(ulong, uint)> numbers = new List<(ulong, uint)>();

            {
                string inp = (input ?? "").Trim();
                if (inp.StartsWith("0x") || inp.StartsWith("0X"))
                    inp = inp.Substring(2);
                if (inp.EndsWith("h"))
                    inp = inp.Substring(0, inp.Length - 1);

                ulong x;
                if (ulong.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out x))
                    numbers.Add((x, 1));
            }

            {
                string inp = (input ?? "").Trim();

                ulong x;
                if (ulong.TryParse(inp, out x))
                    numbers.Add((x, 2));
            }

            var db = Manager.CurrentDatabase;
            if(db != null && db.Names != null)
            {
                foreach(var pair in db.Names)
                {
                    if(pair.Value == input)
                        numbers.Add((pair.Key, 2));
                }
            }

            foreach(var v in this.Versions)
            {
                HashSet<ulong> didid = new HashSet<ulong>();
                HashSet<uint> didof = new HashSet<uint>();

                if(v.L.Values != null)
                {
                    foreach(var n in numbers)
                    {
                        if ((n.Item2 & 2) == 0)
                            continue;

                        uint off;
                        if(v.L.Values.TryGetValue(n.Item1, out off))
                        {
                            ulong? hash = null;
                            ulong h;
                            if (v.L.Hashes != null && v.L.Hashes.TryGetValue(n.Item1, out h))
                                hash = h;

                            if (didid.Add(n.Item1) || didof.Add(off))
                                this.WriteOne(bld, v.L, n.Item1, off, hash, true, this.checkBox1.Checked);
                        }
                    }
                }

                foreach(var n in numbers)
                {
                    if ((n.Item2 & 1) == 0)
                        continue;

                    ulong id;
                    if(v.Reverse.TryGetValue(unchecked((long)n.Item1), out id))
                    {
                        uint off;
                        if(v.L.Values.TryGetValue(id, out off))
                        {
                            ulong? hash = null;
                            ulong h;
                            if (v.L.Hashes != null && v.L.Hashes.TryGetValue(id, out h))
                                hash = h;

                            if (didid.Add(id) || didof.Add(off))
                                this.WriteOne(bld, v.L, id, off, hash, true, this.checkBox1.Checked);
                        }
                    }
                }
            }

            this.textBox2.Text = bld.ToString();
        }

        private void WriteHeader(StringBuilder bld)
        {
            bld.Append(string.Format("{0,-15}", "Version"));
            bld.Append(string.Format("{0,-10}", "ID"));
            bld.Append(string.Format("{0,-20}", "Address"));
            bld.Append(string.Format("{0,-20}", "Hash"));
            bld.Append("Name");
            bld.AppendLine();
        }

        private void WriteOne(StringBuilder bld, Library l, ulong id, uint offset, ulong? hash, bool delim, bool compact)
        {
            if(compact)
            {
                bld.Append(string.Format("{0,-15}", l.Version.ToString()));
                bld.Append(string.Format("{0,-10}", id.ToString()));
                bld.Append(string.Format("{0,-20}", "0x" + (offset + l.BaseAddress).ToString("X")));
                bld.Append(string.Format("{0,-20}", hash.HasValue ? hash.Value.ToString("X16") : ""));
                string n = "";
                if (id != 0)
                {
                    var db = Manager.CurrentDatabase;
                    if (db != null && db.Names != null && db.Names.Count != 0)
                    {
                        if (db.Names.TryGetValue(id, out n))
                        {
                            if (n.Length > 20)
                                n = n.Substring(0, 18) + "..";
                        }
                    }
                }
                bld.Append(n);
                bld.AppendLine();
                return;
            }

            if (delim && bld.Length != 0)
                bld.AppendLine(" <================================>");

            bld.Append("Version:   ");
            bld.Append(l.Version.ToString());
            bld.AppendLine();

            bld.Append("ID:        ");
            bld.Append(id.ToString());
            bld.AppendLine();

            bld.Append("Address:    0x");
            long addr = l.BaseAddress + offset;
            bld.Append(addr.ToString("X"));
            bld.AppendLine();

            bld.Append("Hash:      ");
            if (hash.HasValue)
                bld.Append(hash.Value.ToString("X16"));
            else
                bld.Append("(null)");
            bld.AppendLine();
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            this.UpdateMe(this.textBox1.Text);
        }

        private void OffsetLookupForm_Load(object sender, EventArgs e)
        {
            var db = Manager.CurrentDatabase;
            if(db != null)
            {
                foreach(var pair in db.Versions)
                {
                    if (pair.Value == null)
                        continue;

                    var vl = new VerLookup();
                    vl.L = pair.Value;
                    
                    if(pair.Value.Values != null)
                    {
                        foreach(var pair2 in pair.Value.Values)
                        {
                            vl.Reverse[pair2.Value] = pair2.Key;
                            vl.Reverse[pair.Value.BaseAddress + pair2.Value] = pair2.Key;
                        }
                    }

                    this.Versions.Add(vl);
                }
            }

            this.Versions.Reverse();
        }
    }
}
