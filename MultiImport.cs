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
    public partial class MultiImport : Form
    {
        public MultiImport()
        {
            InitializeComponent();
        }

        private readonly List<ComboBox>[] boxes = new List<ComboBox>[7];

        private void MultiImport_Load(object sender, EventArgs e)
        {
            boxes[0] = new List<ComboBox> { this.comboBox1, this.comboBox2, this.comboBox3 };
            boxes[1] = new List<ComboBox> { this.comboBox6, this.comboBox5, this.comboBox4 };
            boxes[2] = new List<ComboBox> { this.comboBox9, this.comboBox8, this.comboBox7 };
            boxes[3] = new List<ComboBox> { this.comboBox12, this.comboBox11, this.comboBox10 };
            boxes[4] = new List<ComboBox> { this.comboBox15, this.comboBox14, this.comboBox13 };
            boxes[5] = new List<ComboBox> { this.comboBox18, this.comboBox17, this.comboBox16 };
            boxes[6] = new List<ComboBox> { this.comboBox21, this.comboBox20, this.comboBox19 };

            var db = Manager.CurrentDatabase;
            if (db == null)
                return;

            for(int i = 0; i < boxes.Length; i++)
            {
                var ls = boxes[i];
                foreach(var c in ls)
                {
                    c.Items.Add("");
                    foreach (var v in db.Versions)
                        c.Items.Add(v.Key.ToString());

                    c.SelectedIndex = 0;
                }
            }
        }

        private static string _GetSelected(ComboBox c)
        {
            if(c.SelectedIndex >= 0 && c.SelectedIndex < c.Items.Count)
            {
                var o = c.Items[c.SelectedIndex];
                return o.ToString();
            }

            return "";
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var db = Manager.CurrentDatabase;
            if(db == null)
            {
                MessageBox.Show("Didn't load any database!");
                this.DialogResult = DialogResult.Cancel;
                this.Close();
                return;
            }

            List<PDiff> platforms = new List<PDiff>();
            for(int i = 0; i < boxes.Length; i++)
            {
                var ls = boxes[i];

                if (ls[0].SelectedIndex != 0)
                {
                    if (ls[1].SelectedIndex == 0)
                    {
                        MessageBox.Show("You didn't select previous version on row " + (i + 1).ToString() + "!");
                        return;
                    }

                    Version prev;
                    if (!Version.TryParse(_GetSelected(ls[1]), out prev))
                    {
                        MessageBox.Show("Something went wrong! This is not a valid version: " + _GetSelected(ls[1]));
                        return;
                    }

                    Version cur;
                    if (!Version.TryParse(_GetSelected(ls[0]), out cur))
                    {
                        MessageBox.Show("Something went wrong! This is not a valid version: " + _GetSelected(ls[0]));
                        return;
                    }

                    if(prev.Equals(cur))
                    {
                        MessageBox.Show("Can't select previous and new as same version!");
                        return;
                    }

                    Version cross = new Version();
                    if (ls[2].SelectedIndex != 0)
                    {
                        if (!Version.TryParse(_GetSelected(ls[2]), out cross))
                        {
                            MessageBox.Show("Something went wrong! This is not a valid version: " + _GetSelected(ls[2]));
                            return;
                        }
                    }

                    var p = new PDiff();
                    p.Previous = prev;
                    p.Current = cur;
                    p.Cross = cross;
                    platforms.Add(p);
                }
                else if (ls[1].SelectedIndex != 0 || ls[2].SelectedIndex != 0)
                {
                    MessageBox.Show("You selected something on row " + (i + 1).ToString() + " but the current version was not marked!");
                    return;
                }
            }

            if(platforms.Count == 0)
            {
                MessageBox.Show("Didn't select any platforms!");
                this.DialogResult = DialogResult.Cancel;
                this.Close();
                return;
            }

            foreach(var p in platforms)
            {
                Library l = null;
                if(!db.Versions.TryGetValue(p.Previous, out l))
                {
                    MessageBox.Show("Something went wrong! Missing version in database.");
                    return;
                }

                var v = new VLib();
                v.Version = p.Previous;
                v.Library = l;

                v.IdToOffset = new Dictionary<ulong, uint>(l.Values);
                foreach (var pair in l.Values)
                    v.OffsetToId[pair.Value] = pair.Key;

                p.prev = v;

                l = null;
                if (!db.Versions.TryGetValue(p.Current, out l))
                {
                    MessageBox.Show("Something went wrong! Missing version in database.");
                    return;
                }

                // Technically it could work to just replace? But it's troublesome. Don't comment this out, because we didn't support it below with generating new ID without checking old first!
                if(l.Values != null && l.Values.Count != 0)
                {
                    MessageBox.Show("The current version " + l.Version.ToString() + " is not empty! This could cause issues, aborting.");
                    return;
                }

                v = new VLib();
                v.Version = p.Current;
                v.Library = l;

                if (l.Values != null)
                {
                    v.IdToOffset = new Dictionary<ulong, uint>(l.Values);
                    foreach (var pair in l.Values)
                        v.OffsetToId[pair.Value] = pair.Key;
                }

                p.cur = v;

                if(!p.Cross.Equals(new Version()))
                {
                    l = null;
                    if (!db.Versions.TryGetValue(p.Cross, out l))
                    {
                        MessageBox.Show("Something went wrong! Missing version in database.");
                        return;
                    }

                    if (l.Values == null || l.Values.Count == 0)
                    {
                        MessageBox.Show("The cross version " + l.Version.ToString() + " is empty! This could cause issues, aborting.");
                        return;
                    }

                    v = new VLib();
                    v.Version = p.Cross;
                    v.Library = l;

                    v.IdToOffset = new Dictionary<ulong, uint>(l.Values);
                    foreach (var pair in l.Values)
                        v.OffsetToId[pair.Value] = pair.Key;

                    p.cross = v;
                }
            }

            foreach(var p in platforms)
            {
                p.diff_data = this.LoadFile(p.Previous.ToString(), p.Current.ToString(), p.prev.Library, p.cur.Library);
                if (p.diff_data == null)
                    return;

                if(p.cross != null)
                {
                    p.cross_data = this.LoadFile(p.Cross.ToString(), p.Current.ToString(), p.cross.Library, p.cur.Library);
                    if (p.cross_data == null)
                        return;
                }
            }

            foreach(var p in platforms)
            {
                if (!this.DoDiff(p, db, true))
                    return;
            }

            foreach (var p in platforms)
            {
                if (!this.DoDiff(p, db, false))
                    throw new InvalidOperationException();
            }

            var bld = new StringBuilder();
            bld.AppendLine("Results:");

            foreach(var p in platforms)
            {
                bld.AppendLine();
                bld.AppendLine(p.Current.ToString() + ":");
                bld.AppendLine("Matched: " + p.stats_assigned_simple);
                bld.AppendLine("Removed: " + p.stats_removed);
                bld.AppendLine("Added (total): " + p.stats_added_total);
                bld.AppendLine("Added (new): " + p.stats_added_unique);
                bld.AppendLine("Added (shared): " + p.stats_added_shared);
                bld.AppendLine("Cross-check failed: " + p.stats_crossfailed);
                bld.AppendLine("Cross-check wrong: " + p.stats_wrong);
                bld.AppendLine("Cross-check missing: " + p.stats_missing);
            }

            bld.AppendLine();
            bld.AppendLine("Shared means we didn't actually assign a new ID but shared it with the cross-check version.");
            bld.AppendLine("Failed cross-check is normal and can mean that this portion is not present in cross-check version.");
            bld.AppendLine("Missing cross-check is normal, it means the diff decided to omit this address, usually they are locs that weren't supposed to be there anyway.");
            bld.AppendLine("Wrong cross-check is not normal, and means that the cross-check diff would have assigned a different ID than the one we did now. This may be bad, but unknown for sure.");

            MessageBox.Show(bld.ToString(), "Info");

            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private bool DoDiff(PDiff p, Database db, bool checkPhase)
        {
            if (checkPhase)
            {
                foreach (var pair in p.diff_data.offsets)
                {
                    if (!p.prev.OffsetToId.ContainsKey(pair.Key))
                    {
                        p.stats_missing++;
                        //MessageBox.Show("Previous didn't have an offset marked as an ID in version " + p.Previous.ToString() + "! Do a normal diff first.");
                        //return false;
                    }
                }

                foreach (var k in p.diff_data.prevbad)
                {
                    if (!p.prev.OffsetToId.ContainsKey(k))
                    {
                        p.stats_missing++;
                        //MessageBox.Show("Previous didn't have an offset marked as an ID in version " + p.Previous.ToString() + "! Do a normal diff first.");
                        //return false;
                    }
                }

                // Do we care about missing stuff in cross?
                /*if (p.cross_data != null)
                {
                    foreach (var pair in p.cross_data.offsets)
                    {
                        if (!p.cross.OffsetToId.ContainsKey(pair.Key))
                        {
                            p.stats_missing++;
                            //MessageBox.Show("Cross didn't have an offset marked as an ID in version " + p.Cross.ToString() + "! Do a normal diff first.");
                            //return false;
                        }
                    }

                    foreach (var k in p.cross_data.prevbad)
                    {
                        if (!p.cross.OffsetToId.ContainsKey(k))
                        {
                            p.stats_missing++;
                            //MessageBox.Show("Cross didn't have an offset marked as an ID in version " + p.Cross.ToString() + "! Do a normal diff first.");
                            //return false;
                        }
                    }
                }*/

                return true;
            }

            if (p.cur.Library.Values == null)
                p.cur.Library.Values = new SortedDictionary<ulong, uint>();

            foreach(var pair in p.diff_data.offsets)
            {
                ulong id = 0;
                if (!p.prev.OffsetToId.TryGetValue(pair.Key, out id)) // This is the missing part from before
                    continue;
                
                p.stats_assigned_simple++;
                p.cur.Library.Values[id] = pair.Value;

                if(p.cross_data != null)
                {
                    uint cprev = 0;
                    if (p.cross.IdToOffset.TryGetValue(id, out cprev))
                    {
                        uint cnext = 0;
                        if (p.cross_data.offsets.TryGetValue(cprev, out cnext))
                        {
                            if (cnext != pair.Value)
                                p.stats_wrong++;
                        }
                        else
                            p.stats_crossfailed++;
                    }
                    else
                        p.stats_crossfailed++;
                }
            }

            p.stats_removed += p.diff_data.prevbad.Count;
            
            foreach(var bad in p.diff_data.curbad)
            {
                ulong id = 0;

                p.stats_added_total++;

                if(p.cross_data != null)
                {
                    uint orig = 0;
                    if(p.cross_data.offsets2.TryGetValue(bad, out orig))
                    {
                        // This may fail due to missing from before.
                        p.cross.OffsetToId.TryGetValue(orig, out id);
                    }
                }

                if(id != 0)
                {
                    // Success! didn't create new ID.
                    p.stats_added_shared++;
                }
                else
                {
                    id = ++db.HighVID;
                    p.stats_added_unique++;
                }

                p.cur.Library.Values[id] = bad;
            }

            return true;
        }

        private uint ParseOffset(string text, Library l)
        {
            if (!text.StartsWith("0x"))
                return uint.MaxValue;

            text = text.Substring(2);
            long v;
            if (!long.TryParse(text, System.Globalization.NumberStyles.AllowHexSpecifier, null, out v) || v < 0)
                return uint.MaxValue;

            if (v < l.BaseAddress)
                return uint.MaxValue;

            v -= l.BaseAddress;
            if (v >= uint.MaxValue)
                return uint.MaxValue;

            return (uint)v;
        }

        private FData LoadFile(string ver1, string ver2, Library lib1, Library lib2)
        {
            var of = new OpenFileDialog();
            of.AddExtension = true;
            of.DefaultExt = "txt";
            of.CheckFileExists = true;
            of.Title = "Select the output.txt file from IDADiffCalculator " + ver1 + " to " + ver2;

            if (of.ShowDialog() != DialogResult.OK)
                return null;

            var fi = new System.IO.FileInfo(of.FileName);
            if (!fi.Name.Equals("output.txt", StringComparison.OrdinalIgnoreCase))
            {
                if (MessageBox.Show("The selected file is not output.txt! Continue anyway?", "Warning", MessageBoxButtons.YesNoCancel) != DialogResult.Yes)
                    return null;
            }

            var fi_prev = new System.IO.FileInfo(System.IO.Path.Combine(fi.DirectoryName, "output_unmatched_prev.txt"));
            var fi_next = new System.IO.FileInfo(System.IO.Path.Combine(fi.DirectoryName, "output_unmatched_next.txt"));

            if (!fi_prev.Exists || !fi_next.Exists)
            {
                MessageBox.Show("Failed to find output_unmatched_prev.txt or output_unmatched_next.txt! These two files are also needed.", "Error", MessageBoxButtons.OK);
                return null;
            }

            var f = new FData();

            using(var reader = fi.OpenText())
            {
                string l;
                while((l = reader.ReadLine()) != null)
                {
                    if (l.Length == 0)
                        break;
                }

                while((l = reader.ReadLine()) != null)
                {
                    var spl = l.Split(new[] { '\t' }, StringSplitOptions.None);
                    if(spl.Length != 2)
                    {
                        MessageBox.Show("output.txt file had invalid format!");
                        return null;
                    }

                    uint k = this.ParseOffset(spl[0], lib1);
                    if(k == uint.MaxValue)
                    {
                        MessageBox.Show("Failed to parse offset from output.txt file!");
                        return null;
                    }

                    uint v = this.ParseOffset(spl[1], lib2);
                    if(v == uint.MaxValue)
                    {
                        MessageBox.Show("Failed to parse offset from output.txt file!");
                        return null;
                    }

                    f.offsets.Add(k, v);
                    f.offsets2.Add(v, k);
                }
            }

            using(var reader = fi_prev.OpenText())
            {
                string l;
                while((l = reader.ReadLine()) != null)
                {
                    if (l.Length == 0)
                        continue;

                    uint k = this.ParseOffset(l, lib1);
                    if(k == uint.MaxValue)
                    {
                        MessageBox.Show("Failed to parse offset from output_unmatched_prev.txt!");
                        return null;
                    }

                    f.prevbad.Add(k);
                }
            }

            using (var reader = fi_next.OpenText())
            {
                string l;
                while ((l = reader.ReadLine()) != null)
                {
                    if (l.Length == 0)
                        continue;

                    uint k = this.ParseOffset(l, lib2);
                    if (k == uint.MaxValue)
                    {
                        MessageBox.Show("Failed to parse offset from output_unmatched_next.txt!");
                        return null;
                    }

                    f.curbad.Add(k);
                }
            }

            return f;
        }

        private sealed class FData
        {
            internal Dictionary<uint, uint> offsets = new Dictionary<uint, uint>();
            internal Dictionary<uint, uint> offsets2 = new Dictionary<uint, uint>();
            internal List<uint> prevbad = new List<uint>();
            internal List<uint> curbad = new List<uint>();
        }

        private sealed class VLib
        {
            internal Version Version;
            internal Library Library;
            internal Dictionary<uint, ulong> OffsetToId = new Dictionary<uint, ulong>();
            internal Dictionary<ulong, uint> IdToOffset = new Dictionary<ulong, uint>();
        }

        private sealed class PDiff
        {
            internal Version Previous;
            internal Version Current;
            internal Version Cross;

            internal VLib prev;
            internal VLib cur;
            internal VLib cross;

            internal FData diff_data;
            internal FData cross_data;

            internal int stats_assigned_simple;
            internal int stats_removed;
            internal int stats_added_total;
            internal int stats_added_shared;
            internal int stats_added_unique;
            internal int stats_wrong;
            internal int stats_crossfailed;
            internal int stats_missing;
        }
    }
}
