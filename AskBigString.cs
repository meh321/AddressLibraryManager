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
    public partial class AskBigString : Form
    {
        public AskBigString()
        {
            InitializeComponent();
        }

        internal enum BigStringTypes : int
        {
            OffsetMap,
            NameMap,
        }

        internal BigStringTypes BigStringType;
        internal object BigStringResult;

        internal object GetBigString(ref string error)
        {
            SortedDictionary<ulong, uint> offsets = new SortedDictionary<ulong, uint>();
            SortedDictionary<ulong, string> names = new SortedDictionary<ulong, string>();

            string text = this.textBox1.Text;
            var spl = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            for (int i = 0; i < spl.Length; i++)
            {
                var l = spl[i].Trim();
                if (l.Length == 0)
                    continue;

                int ix = l.IndexOf(' ');
                if(ix < 0)
                {
                    error = "Invalid format on line " + (i + 1) + ": " + spl[i];
                    return null;
                }

                ulong id;
                if(!ulong.TryParse(l.Substring(0, ix), System.Globalization.NumberStyles.None, null, out id))
                {
                    error = "Invalid format on line " + (i + 1) + ": " + spl[i];
                    return null;
                }

                string k = l.Substring(ix + 1).Trim();

                switch (this.BigStringType)
                {
                    case BigStringTypes.OffsetMap:
                        {
                            uint off;
                            if(!uint.TryParse(k, System.Globalization.NumberStyles.AllowHexSpecifier, null, out off))
                            {
                                error = "Invalid format on line " + (i + 1) + ": " + spl[i];
                                return null;
                            }

                            if(offsets.ContainsKey(id))
                            {
                                error = "Duplicate identifier on line " + (i + 1) + ": " + id;
                                return null;
                            }

                            offsets[id] = off;
                        }
                        break;

                    case BigStringTypes.NameMap:
                        {
                            if(k.Length == 0)
                            {
                                error = "Invalid format on line " + (i + 1) + ": " + spl[i];
                                return null;
                            }

                            if(names.ContainsKey(id))
                            {
                                error = "Duplicate identifier on line " + (i + 1) + ": " + id;
                                return null;
                            }

                            names[id] = k;
                        }
                        break;

                    default:
                        throw new NotImplementedException();
                }
            }

            switch(this.BigStringType)
            {
                case BigStringTypes.NameMap: return names;
                case BigStringTypes.OffsetMap: return offsets;
                default:
                    throw new NotImplementedException();
            }
        }

        internal void SetBigString(object value)
        {
            var str = new StringBuilder();
            switch(this.BigStringType)
            {
                case BigStringTypes.OffsetMap:
                    {
                        SortedDictionary<ulong, uint> offsets = (SortedDictionary<ulong, uint>)value;
                        if(offsets != null)
                        {
                            foreach(var pair in offsets)
                            {
                                str.Append(pair.Key.ToString());
                                str.Append(' ');
                                str.Append(pair.Value.ToString("X"));
                                str.AppendLine();
                            }
                        }
                    }
                    break;

                case BigStringTypes.NameMap:
                    {
                        SortedDictionary<ulong, string> names = (SortedDictionary<ulong, string>)value;
                        if (names != null)
                        {
                            foreach (var pair in names)
                            {
                                if (string.IsNullOrEmpty(pair.Value))
                                    continue;

                                str.Append(pair.Key.ToString());
                                str.Append(' ');
                                str.Append(pair.Value);
                                str.AppendLine();
                            }
                        }
                    }
                    break;

                default:
                    throw new NotImplementedException();
            }

            this.textBox1.Text = str.ToString();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string error = null;
            this.BigStringResult = this.GetBigString(ref error);
            if(error != null)
            {
                MessageBox.Show(error, "Error", MessageBoxButtons.OK);
                return;
            }

            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }
}
