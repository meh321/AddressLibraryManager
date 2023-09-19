using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AddressLibraryManager
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if(Manager.Modified != 0)
            {
                var result = MessageBox.Show("Are you sure you want to exit? You will lose any unsaved data.", "Warning", MessageBoxButtons.YesNoCancel);
                if(result != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
            }
        }

        private void newToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if(Manager.Modified != 0)
            {
                var result = MessageBox.Show("Are you sure you want to do that? You will lose any unsaved data.", "Warning", MessageBoxButtons.YesNoCancel);
                if (result != DialogResult.Yes)
                    return;
            }

            Manager.Modified = 0;
            Manager.CurrentFile = null;
            Manager.CurrentDatabase = new Database();
            this.UpdateTitle();
            this.UpdateLeftBox();
        }

        private void toolStripMenuItem1_Click(object sender, EventArgs e)
        {
            if (Manager.Modified != 0)
            {
                var result = MessageBox.Show("Are you sure you want to do that? You will lose any unsaved data.", "Warning", MessageBoxButtons.YesNoCancel);
                if (result != DialogResult.Yes)
                    return;
            }

            var of = new OpenFileDialog();
            of.AddExtension = true;
            of.CheckFileExists = true;
            of.DefaultExt = "relib";
            of.Multiselect = false;
            of.Title = "Open address library database";

            var r = of.ShowDialog();
            if (r != DialogResult.OK)
                return;

            try
            {
                var fi = new System.IO.FileInfo(of.FileName);
                var db = new Database();
                db.LoadAll(fi);

                Manager.Modified = 0;
                Manager.CurrentFile = fi;
                Manager.CurrentDatabase = db;
            }
            catch(Exception ex)
            {
                ReportError(ex);
                return;
            }

            this.UpdateTitle();
            this.UpdateLeftBox();
        }

        internal static void ReportError(Exception ex)
        {
            var str = new StringBuilder();
            str.Append(ex.GetType().Name);
            str.Append(": ");
            str.Append(ex.Message ?? "");
            str.AppendLine();
            str.Append(ex.StackTrace);
            MessageBox.Show("Error", str.ToString(), MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        internal void UpdateTitle()
        {
            var str = new StringBuilder();
            str.Append("Address Library Manager");

            if(Manager.CurrentDatabase != null)
            {
                str.Append(" - ");
                if (Manager.CurrentFile == null)
                    str.Append("New database");
                else
                    str.Append(Manager.CurrentFile.Name);

                if (Manager.Modified != 0)
                    str.Append(" *");
            }

            string title = str.ToString();
            if (this.Text != title)
                this.Text = title;
        }

        internal void UpdateLeftBox(string forceSelect = null)
        {
            this.DisableLeftBoxEvents++;
            {
                string sel = null;
                if (forceSelect != null)
                    sel = forceSelect;
                else if (this.listBox1.SelectedIndex >= 0 && this.listBox1.SelectedIndex < this.listBox1.Items.Count)
                    sel = this.listBox1.Items[this.listBox1.SelectedIndex].ToString();

                this.listBox1.SelectedIndex = -1;
                this.listBox1.Items.Clear();

                if (Manager.CurrentDatabase != null)
                {
                    this.listBox1.Items.Add("Base");
                    this.listBox1.Items.Add("Names");
                    if (Manager.CurrentDatabase.Versions != null)
                    {
                        foreach (var pair in Manager.CurrentDatabase.Versions)
                            this.listBox1.Items.Add(pair.Key);
                    }
                }

                if(sel != null)
                {
                    int ix = -1;
                    for(int i = 0; i < this.listBox1.Items.Count; i++)
                    {
                        if(this.listBox1.Items[i].ToString() == sel)
                        {
                            ix = i;
                            break;
                        }
                    }

                    if (ix < 0)
                    {
                        int p = this.DisableLeftBoxEvents;
                        this.DisableLeftBoxEvents = 0;
                        this.listBox1.ClearSelected();
                        this.DisableLeftBoxEvents = p;
                    }
                    else if(forceSelect != null)
                    {
                        int p = this.DisableLeftBoxEvents;
                        this.DisableLeftBoxEvents = 0;
                        this.listBox1.SelectedIndex = ix;
                        this.DisableLeftBoxEvents = p;
                    }
                    else
                    {
                        this.listBox1.SelectedIndex = ix;
                    }
                }
            }
            this.DisableLeftBoxEvents--;
        }

        private void saveToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (Manager.Modified == 0)
                return;

            if(Manager.CurrentDatabase == null)
            {
                MessageBox.Show("There's no database to save! Create New or Load an existing one first.");
                return;
            }

            if(Manager.CurrentFile == null)
            {
                _DoSaveAs();
                return;
            }

            try
            {
                Manager.CurrentDatabase.SaveAll(Manager.CurrentFile, Manager.Modified);
                Manager.Modified = 0;
            }
            catch(Exception ex)
            {
                ReportError(ex);
                return;
            }

            UpdateTitle();
        }

        private void _DoSaveAs()
        {
            var of = new SaveFileDialog();
            of.AddExtension = true;
            of.DefaultExt = "relib";
            of.Title = "Save address library database";
            of.OverwritePrompt = true;

            var r = of.ShowDialog();
            if (r != DialogResult.OK)
                return;

            try
            {
                var fi = new System.IO.FileInfo(of.FileName);
                Manager.CurrentDatabase.SaveAll(fi);
                Manager.CurrentFile = fi;
                Manager.Modified = 0;
            }
            catch (Exception ex)
            {
                ReportError(ex);
                return;
            }

            UpdateTitle();
        }

        private void saveAsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("There's no database to save! Create New or Load an existing one first.");
                return;
            }

            _DoSaveAs();
        }

        private void exitToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private int DisableLeftBoxEvents = 0;
        private int DisableRightBoxEvents = 0;

        private LeftSelection CurrentSelection;

        private struct LeftSelection
        {
            internal int Type;
            internal Version Version;
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (this.DisableLeftBoxEvents > 0)
                return;

            if(this.listBox1.SelectedIndex >= 0 && this.listBox1.SelectedIndex < this.listBox1.Items.Count)
            {
                if(this.listBox1.SelectedIndex == 0)
                {
                    if (this.CurrentSelection.Type == 1)
                        return;

                    if (this.CurrentSelection.Type != 0)
                    {
                        switch (this.CurrentSelection.Type)
                        {
                            case 1: this.groupBox1.Visible = false; break;
                            case 2: this.groupBox2.Visible = false; break;
                            case 3: this.groupBox3.Visible = false; break;
                            default: throw new NotImplementedException();
                        }
                    }

                    this.CurrentSelection = new LeftSelection() { Type = 1 };
                    this.UpdateRightBox();
                    this.groupBox1.Visible = true;
                }
                else if (this.listBox1.SelectedIndex == 1)
                {
                    if (this.CurrentSelection.Type == 2)
                        return;

                    if (this.CurrentSelection.Type != 0)
                    {
                        switch (this.CurrentSelection.Type)
                        {
                            case 1: this.groupBox1.Visible = false; break;
                            case 2: this.groupBox2.Visible = false; break;
                            case 3: this.groupBox3.Visible = false; break;
                            default: throw new NotImplementedException();
                        }
                    }

                    this.CurrentSelection = new LeftSelection() { Type = 2 };
                    this.UpdateRightBox();
                    this.groupBox2.Visible = true;
                }
                else
                {
                    if(this.CurrentSelection.Type != 0 && this.CurrentSelection.Type != 3)
                    {
                        switch (this.CurrentSelection.Type)
                        {
                            case 1: this.groupBox1.Visible = false; break;
                            case 2: this.groupBox2.Visible = false; break;
                            case 3: this.groupBox3.Visible = false; break;
                            default: throw new NotImplementedException();
                        }
                    }

                    var sel = (Version)this.listBox1.Items[this.listBox1.SelectedIndex];
                    if (this.CurrentSelection.Type == 3 && this.CurrentSelection.Version.Equals(sel))
                        return;

                    this.CurrentSelection = new LeftSelection() { Type = 3, Version = sel };
                    this.UpdateRightBox();
                    if(!groupBox3.Visible)
                        this.groupBox3.Visible = true;
                }
            }
            else
            {
                if(this.CurrentSelection.Type != 0)
                {
                    switch(this.CurrentSelection.Type)
                    {
                        case 1: this.groupBox1.Visible = false; break;
                        case 2: this.groupBox2.Visible = false; break;
                        case 3: this.groupBox3.Visible = false; break;
                        default: throw new NotImplementedException();
                    }
                }

                this.CurrentSelection = new LeftSelection();
            }
        }

        internal void UpdateRightBox()
        {
            this.DisableRightBoxEvents++;
            if (Manager.CurrentDatabase != null)
            {
                switch (this.CurrentSelection.Type)
                {
                    case 0:
                        break;

                    case 1:
                        this.textBox1.Text = Manager.CurrentDatabase.HighVID.ToString();
                        this.textBox2.Text = Manager.CurrentDatabase.TargetModuleName;
                        this.textBox3.Text = Manager.CurrentDatabase.PointerSize.ToString();
                        break;

                    case 2:
                        break;

                    case 3:
                        {
                            Library lib = null;
                            if (Manager.CurrentDatabase.Versions != null)
                                Manager.CurrentDatabase.Versions.TryGetValue(this.CurrentSelection.Version, out lib);

                            if (lib != null)
                            {
                                this.textBox4.Text = lib.OverwriteTargetModuleName ?? "";
                                this.textBox5.Text = lib.BaseAddress.ToString("X");
                            }
                        }
                        break;

                    default:
                        throw new NotImplementedException();
                }
            }
            this.DisableRightBoxEvents--;
        }

        internal void MarkModified(uint mask)
        {
            bool hadModified = Manager.Modified != 0;
            Manager.Modified |= mask;

            if (mask != 0 && !hadModified)
                this.UpdateTitle();
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            if (this.DisableRightBoxEvents > 0)
                return;

            var db = Manager.CurrentDatabase;
            if (db == null || db.TargetModuleName == this.textBox2.Text)
                return;

            db.TargetModuleName = this.textBox2.Text;
            this.MarkModified(1);
        }

        private void textBox3_TextChanged(object sender, EventArgs e)
        {
            if (this.DisableRightBoxEvents > 0)
                return;

            var db = Manager.CurrentDatabase;
            if (db == null)
                return;

            int ps = 0;
            if (!int.TryParse(this.textBox3.Text, System.Globalization.NumberStyles.None, null, out ps) || ps <= 0)
                return;

            if (db.PointerSize == ps)
                return;

            db.PointerSize = ps;
            this.MarkModified(1);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.groupBox1.Dock = DockStyle.Fill;
            this.groupBox2.Dock = DockStyle.Fill;
            this.groupBox3.Dock = DockStyle.Fill;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if(this.CurrentSelection.Type != 3)
            {
                MessageBox.Show("You need to select a version to delete first!", "Error", MessageBoxButtons.OK);
                return;
            }

            if(Manager.CurrentDatabase == null)
            {
                MessageBox.Show("A database needs to be loaded first!");
                return;
            }

            if(Manager.CurrentDatabase.Versions == null || !Manager.CurrentDatabase.Versions.ContainsKey(this.CurrentSelection.Version))
            {
                MessageBox.Show("This version has already been deleted!");
                return;
            }

            Manager.CurrentDatabase.Versions.Remove(this.CurrentSelection.Version);
            this.MarkModified(1);
            this.UpdateLeftBox();
        }

        internal static string AskShortString(string title, string text = "")
        {
            var f = new AskShortString();
            f.Text = title;
            f.textBox1.Text = text ?? "";
            if (f.ShowDialog() != DialogResult.OK)
                return null;
            return f.textBox1.Text;
        }

        internal static Version? AskVersion(IEnumerable<Version> all, string title = null, string errorIfEmpty = null)
        {
            if(all != null)
            {
                var ls = all.ToList();
                if(ls.Count != 0)
                {
                    if (ls.Count > 1)
                        ls.Sort();

                    var f = new SelectVersionForm();
                    f.AllVersions = ls;
                    if (title != null)
                        f.Text = title;

                    if (f.ShowDialog() == DialogResult.OK)
                        return f.SelectedVersion;
                    return null;
                }
            }

            if (errorIfEmpty != null)
                MessageBox.Show(errorIfEmpty, "Error", MessageBoxButtons.OK);
            return null;
        }

        internal static SortedDictionary<ulong, uint> AskOffsets(SortedDictionary<ulong, uint> all, string title = null)
        {
            var f = new AskBigString();
            if(!string.IsNullOrEmpty(title))
                f.Text = title;
            f.BigStringType = AskBigString.BigStringTypes.OffsetMap;
            f.SetBigString(all);
            var r = f.ShowDialog();
            if (r != DialogResult.OK)
                return null;

            return (SortedDictionary<ulong, uint>)f.BigStringResult;
        }

        internal static SortedDictionary<ulong, string> AskNames(SortedDictionary<ulong, string> all, string title = null)
        {
            var f = new AskBigString();
            if (!string.IsNullOrEmpty(title))
                f.Text = title;
            f.BigStringType = AskBigString.BigStringTypes.NameMap;
            f.SetBigString(all);
            var r = f.ShowDialog();
            if (r != DialogResult.OK)
                return null;

            return (SortedDictionary<ulong, string>)f.BigStringResult;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("A database needs to be loaded first!");
                return;
            }

            string verstr = AskShortString("Enter version");
            if (verstr == null)
                return;

            Version v;
            if(!Version.TryParse(verstr, out v))
            {
                MessageBox.Show("Invalid version format! Valid version number example is 1.5.97.0", "Error", MessageBoxButtons.OK);
                return;
            }

            if(Manager.CurrentDatabase.Versions != null && Manager.CurrentDatabase.Versions.ContainsKey(v))
            {
                MessageBox.Show("This version already exists in current database!", "Error", MessageBoxButtons.OK);
                return;
            }

            var lib = new Library();
            lib.Version = v;

            if (Manager.CurrentDatabase.Versions == null)
                Manager.CurrentDatabase.Versions = new SortedDictionary<Version, Library>();
            Manager.CurrentDatabase.Versions.Add(v, lib);
            this.MarkModified(1);

            this.UpdateLeftBox(v.ToString());
        }

        private void button3_Click(object sender, EventArgs e)
        {
            try
            {
                if (Manager.CurrentDatabase == null)
                {
                    MessageBox.Show("A database needs to be loaded first!");
                    return;
                }

                if (Manager.CurrentDatabase.Versions == null || Manager.CurrentDatabase.Versions.Count < 2)
                {
                    MessageBox.Show("You don't have enough versions in the database declared!");
                    return;
                }

                var prevVer = AskVersion(Manager.CurrentDatabase.Versions.Keys, "Select previous version");
                if (!prevVer.HasValue)
                    return;

                var nextVer = AskVersion(Manager.CurrentDatabase.Versions.Keys.Where(q => !q.Equals(prevVer.Value)), "Select next version");
                if (!nextVer.HasValue)
                    return;

                if (this.CurrentSelection.Type != 3 || (!prevVer.Value.Equals(this.CurrentSelection.Version) && !nextVer.Value.Equals(this.CurrentSelection.Version)))
                {
                    if (MessageBox.Show("Neither the previous or next version is currently selected version! Continue anyway?", "Warning", MessageBoxButtons.YesNoCancel) != DialogResult.Yes)
                        return;
                }

                var of = new OpenFileDialog();
                of.AddExtension = true;
                of.DefaultExt = "txt";
                of.CheckFileExists = true;
                of.Title = "Select the output.txt file from IDADiffCalculator";

                if (of.ShowDialog() != DialogResult.OK)
                    return;

                var fi = new System.IO.FileInfo(of.FileName);
                if (!fi.Name.Equals("output.txt", StringComparison.OrdinalIgnoreCase))
                {
                    if (MessageBox.Show("The selected file is not output.txt! Continue anyway?", "Warning", MessageBoxButtons.YesNoCancel) != DialogResult.Yes)
                        return;
                }

                var fi_prev = new System.IO.FileInfo(System.IO.Path.Combine(fi.DirectoryName, "output_unmatched_prev.txt"));
                var fi_next = new System.IO.FileInfo(System.IO.Path.Combine(fi.DirectoryName, "output_unmatched_next.txt"));

                if (!fi_prev.Exists || !fi_next.Exists)
                {
                    MessageBox.Show("Failed to find output_unmatched_prev.txt or output_unmatched_next.txt! These two files are also needed.", "Error", MessageBoxButtons.OK);
                    return;
                }

                var prev_lib = Manager.CurrentDatabase.Versions[prevVer.Value];
                var next_lib = Manager.CurrentDatabase.Versions[nextVer.Value];
                
                if (prev_lib == next_lib)
                    throw new InvalidOperationException("prev_lib == next_lib");
                
                int newID = 0;
                int assignedID1 = 0;
                int assignedID2 = 0;
                bool modified = false;
                int errorMatch = 0;

                {
                    var all = new _loadHelper();
                    if(prev_lib.Values != null)
                    {
                        foreach (var pair in prev_lib.Values)
                            all.AddNew(new _loadHelper._loadEntry() { Prev = pair.Value, Next = uint.MaxValue, Id = pair.Key }, false);
                    }
                    if(next_lib.Values != null)
                    {
                        foreach(var pair in next_lib.Values)
                        {
                            var v = all.GetId(pair.Key);
                            if (v == null)
                                all.AddNew(new _loadHelper._loadEntry() { Prev = uint.MaxValue, Next = pair.Value, Id = pair.Key }, false);
                            else
                            {
                                all.Remove(v, true);
                                v.Next = pair.Value;
                                all.AddNew(v, true);
                            }
                        }
                    }
                    using (var sw = new System.IO.StreamReader(fi.FullName, new UTF8Encoding(false)))
                    {
                        string l;
                        while((l = sw.ReadLine()) != null)
                        {
                            if (l.Length == 0)
                                break;
                        }

                        while((l = sw.ReadLine()) != null)
                        {
                            if (l.Length == 0)
                                continue;

                            int ix = l.IndexOf('\t');
                            if (ix < 0)
                                continue;

                            string first = l.Substring(2, ix - 2);
                            string second = l.Substring(ix + 3);

                            long a, b;
                            if (!long.TryParse(first, System.Globalization.NumberStyles.AllowHexSpecifier, null, out a) || !long.TryParse(second, System.Globalization.NumberStyles.AllowHexSpecifier, null, out b))
                                throw new FormatException("Bad format: " + l);

                            a -= prev_lib.BaseAddress;
                            b -= next_lib.BaseAddress;
                            if (a < 0 || b < 0 || a > 0x40000000 || b > 0x40000000)
                                throw new FormatException("Invalid address: " + l);

                            uint xa = (uint)a;
                            uint xb = (uint)b;

                            var v = all.GetPrev(xa);
                            if(v != null)
                            {
                                if (v.Next != uint.MaxValue && v.Next != xb)
                                    errorMatch++;
                                if (v.Next != xb)
                                {
                                    all.Remove(v, true);
                                    v.Next = xb;
                                    all.AddNew(v, true);
                                }
                            }
                            else
                            {
                                v = all.GetNext(xb);
                                if (v != null)
                                {
                                    if (v.Prev != uint.MaxValue && v.Prev != xa)
                                        errorMatch++;
                                    if (v.Prev != xa)
                                    {
                                        all.Remove(v, true);
                                        v.Prev = xa;
                                        all.AddNew(v, true);
                                    }
                                }
                                else
                                    all.AddNew(new _loadHelper._loadEntry() { Prev = xa, Next = xb, Id = 0 }, false);
                            }
                        }
                    }
                    using (var sw = new System.IO.StreamReader(fi_prev.FullName, new UTF8Encoding(false)))
                    {
                        string l;
                        while ((l = sw.ReadLine()) != null)
                        {
                            if (l.Length == 0)
                                continue;
                            
                            string first = l.Substring(2);

                            long a;
                            if (!long.TryParse(first, System.Globalization.NumberStyles.AllowHexSpecifier, null, out a))
                                throw new FormatException("Bad format: " + l);

                            a -= prev_lib.BaseAddress;
                            if (a < 0 || a > 0x40000000)
                                throw new FormatException("Invalid address: " + l);

                            uint xa = (uint)a;

                            var v = all.GetPrev(xa);
                            if (v == null)
                                all.AddNew(new _loadHelper._loadEntry() { Prev = xa, Next = uint.MaxValue, Id = 0 }, false);
                        }
                    }
                    using (var sw = new System.IO.StreamReader(fi_next.FullName, new UTF8Encoding(false)))
                    {
                        string l;
                        while ((l = sw.ReadLine()) != null)
                        {
                            if (l.Length == 0)
                                continue;

                            string first = l.Substring(2);

                            long a;
                            if (!long.TryParse(first, System.Globalization.NumberStyles.AllowHexSpecifier, null, out a))
                                throw new FormatException("Bad format: " + l);

                            a -= next_lib.BaseAddress;
                            if (a < 0 || a > 0x40000000)
                                throw new FormatException("Invalid address: " + l);

                            uint xa = (uint)a;

                            var v = all.GetNext(xa);
                            if (v == null)
                                all.AddNew(new _loadHelper._loadEntry() { Prev = uint.MaxValue, Next = xa, Id = 0 }, false);
                        }
                    }

                    if(errorMatch > 0)
                    {
                        if (MessageBox.Show("Had some matches that were previously marked differently, this could lead to bad or broken library. Continue anyway?", "Warning", MessageBoxButtons.YesNoCancel) != DialogResult.Yes)
                            return;
                    }

                    if (all.All.Count > 1)
                    {
                        all.All.Sort((u, v) =>
                        {
                            int c = u.Id.CompareTo(v.Id);
                            if (c != 0)
                                return c;

                            uint a = u.Prev;
                            if (a == uint.MaxValue)
                                a = u.Next;

                            uint b = v.Prev;
                            if (b == uint.MaxValue)
                                b = v.Next;

                            return a.CompareTo(b);
                        });
                    }

                    for (int i = 0; i < all.All.Count; i++)
                    {
                        var t = all.All[i];
                        ulong id = t.Id;
                        if (id == 0)
                        {
                            id = ++Manager.CurrentDatabase.HighVID;
                            modified = true;
                            newID++;
                        }

                        if(t.Prev != uint.MaxValue)
                        {
                            var m = prev_lib.Values;
                            if(m == null)
                            {
                                m = new SortedDictionary<ulong, uint>();
                                prev_lib.Values = m;
                            }

                            uint pv;
                            if(!m.TryGetValue(id, out pv) || pv != t.Prev)
                            {
                                m[id] = t.Prev;
                                modified = true;
                                assignedID1++;
                            }
                        }

                        if(t.Next != uint.MaxValue)
                        {
                            var m = next_lib.Values;
                            if(m == null)
                            {
                                m = new SortedDictionary<ulong, uint>();
                                next_lib.Values = m;
                            }

                            uint pv;
                            if(!m.TryGetValue(id, out pv) || pv != t.Next)
                            {
                                m[id] = t.Next;
                                modified = true;
                                assignedID2++;
                            }
                        }
                    }
                }

                if(newID > 0 || modified)
                    this.MarkModified(1);

                MessageBox.Show("Ok. Assigned " + assignedID1 + " ID in previous version, and " + assignedID2 + " in next version. " + newID + " of the IDs were newly created.");
            }
            catch(Exception ex)
            {
                ReportError(ex);
            }
        }

        private sealed class _loadHelper
        {
            internal sealed class _loadEntry
            {
                internal uint Prev;
                internal uint Next;
                internal ulong Id;
            }

            internal readonly Dictionary<uint, _loadEntry> MapPrev = new Dictionary<uint, _loadEntry>();
            internal readonly Dictionary<uint, _loadEntry> MapNext = new Dictionary<uint, _loadEntry>();
            internal readonly Dictionary<ulong, _loadEntry> MapId = new Dictionary<ulong, _loadEntry>();
            internal readonly List<_loadEntry> All = new List<_loadEntry>();

            internal void AddNew(_loadEntry e, bool noadd)
            {
                if (e.Prev != uint.MaxValue)
                    this.MapPrev[e.Prev] = e;
                if (e.Next != uint.MaxValue)
                    this.MapNext[e.Next] = e;
                if (e.Id != 0)
                    this.MapId[e.Id] = e;
                if(!noadd)
                    this.All.Add(e);
            }

            internal void Remove(_loadEntry e, bool norem)
            {
                if (e.Prev != uint.MaxValue)
                    this.MapPrev.Remove(e.Prev);
                if (e.Next != uint.MaxValue)
                    this.MapNext.Remove(e.Next);
                if (e.Id != 0)
                    this.MapId.Remove(e.Id);
                if(!norem)
                    this.All.Remove(e);
            }

            internal _loadEntry GetPrev(uint value)
            {
                _loadEntry v;
                this.MapPrev.TryGetValue(value, out v);
                return v;
            }

            internal _loadEntry GetNext(uint value)
            {
                _loadEntry v;
                this.MapNext.TryGetValue(value, out v);
                return v;
            }

            internal _loadEntry GetId(ulong id)
            {
                _loadEntry v;
                this.MapId.TryGetValue(id, out v);
                return v;
            }
        }

        private static int FindIndex_Prev(List<Tuple<uint, uint, ulong>> list, uint value)
        {
            for(int i = 0; i < list.Count; i++)
            {
                if (list[i].Item1 == value)
                    return i;
            }

            return -1;
        }

        private static int FindIndex_Next(List<Tuple<uint, uint, ulong>> list, uint value)
        {
            for(int i = 0; i < list.Count; i++)
            {
                if (list[i].Item2 == value)
                    return i;
            }

            return -1;
        }

        private static int FindIndex_Id(List<Tuple<uint, uint, ulong>> list, ulong value)
        {
            for(int i = 0; i < list.Count; i++)
            {
                if (list[i].Item3 == value)
                    return i;
            }

            return -1;
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if(Manager.CurrentDatabase == null || this.CurrentSelection.Type != 3)
            {
                MessageBox.Show("You need to select a version first!");
                return;
            }

            var map = Manager.CurrentDatabase.Versions;
            Library l;
            if(map == null || !map.TryGetValue(this.CurrentSelection.Version, out l))
            {
                MessageBox.Show("Something went wrong!");
                return;
            }

            try
            {
                string fileName = "versionlib-" + string.Join("-", l.Version.Numbers) + ".bin";
                var fi = new System.IO.FileInfo(fileName);
                l.WriteAddressLibrary(Manager.CurrentDatabase, fi);
                MessageBox.Show("Wrote " + fileName + " to " + fi.DirectoryName + "!");
            }
            catch(Exception ex)
            {
                ReportError(ex);
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("You must load the database first!");
                return;
            }

            var map = Manager.CurrentDatabase.Versions;
            if (map == null || map.Count == 0)
            {
                MessageBox.Show("Something went wrong!");
                return;
            }

            try
            {
                int did = 0;
                string dirpath = null;
                foreach (var pair in map)
                {
                    string fileName = "versionlib-" + string.Join("-", pair.Key.Numbers) + ".bin";
                    var fi = new System.IO.FileInfo(fileName);
                    pair.Value.WriteAddressLibrary(Manager.CurrentDatabase, fi);
                    did++;
                    if (dirpath == null)
                        dirpath = fi.DirectoryName;
                }
                if (dirpath == null)
                    dirpath = "nowhere";
                MessageBox.Show("Wrote " + did + " address libraries to " + dirpath + "!");
            }
            catch (Exception ex)
            {
                ReportError(ex);
            }
        }

        private void button6_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("You must load the database first!");
                return;
            }

            var map = Manager.CurrentDatabase.Versions;
            Library lib;
            if (map == null || map.Count == 0 || this.CurrentSelection.Type != 3 || !map.TryGetValue(this.CurrentSelection.Version, out lib))
            {
                MessageBox.Show("Something went wrong!");
                return;
            }

            try
            {
                string suffix = string.Join("-", lib.Version.Numbers);

                var fi = new System.IO.FileInfo("offsets-" + suffix + ".txt");
                using (var sw = new System.IO.StreamWriter(fi.FullName, false))
                {
                    if (lib.Values != null)
                    {
                        foreach(var pair in lib.Values)
                        {
                            sw.Write(string.Format("{0,-9}", pair.Key.ToString()));
                            sw.Write(' ');
                            sw.Write((pair.Value + lib.BaseAddress).ToString("X"));
                            sw.WriteLine();
                        }
                    }
                }

                MessageBox.Show("Wrote offsets-" + suffix + ".txt to " + fi.DirectoryName + "!");
            }
            catch(Exception ex)
            {
                ReportError(ex);
            }
        }

        private void button7_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("You must load the database first!");
                return;
            }

            var map = Manager.CurrentDatabase.Versions;
            Library lib;
            if (map == null || map.Count == 0 || this.CurrentSelection.Type != 3 || !map.TryGetValue(this.CurrentSelection.Version, out lib))
            {
                MessageBox.Show("Something went wrong!");
                return;
            }

            var all = AskOffsets(lib.Values, "Edit offsets manually");
            if (all == null)
                return;

            lib.Values = all;
            this.MarkModified(1);
        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {
            if (this.DisableRightBoxEvents > 0)
                return;

            var db = Manager.CurrentDatabase;
            Library lib;
            if (db == null || this.CurrentSelection.Type != 3 || db.Versions == null || !db.Versions.TryGetValue(this.CurrentSelection.Version, out lib))
                return;

            string has = this.textBox4.Text;
            if (has.Length == 0)
                has = null;

            if (lib.OverwriteTargetModuleName == has)
                return;

            lib.OverwriteTargetModuleName = has;
            this.MarkModified(1);
        }

        private void textBox5_TextChanged(object sender, EventArgs e)
        {
            if (this.DisableRightBoxEvents > 0)
                return;

            var db = Manager.CurrentDatabase;
            Library lib;
            if (db == null || this.CurrentSelection.Type != 3 || db.Versions == null || !db.Versions.TryGetValue(this.CurrentSelection.Version, out lib))
                return;

            long addr = 0;

            string has = this.textBox5.Text;
            if (has.Length != 0)
            {
                if (!long.TryParse(has, System.Globalization.NumberStyles.AllowHexSpecifier, null, out addr))
                    return;
            }

            if (lib.BaseAddress == addr)
                return;

            lib.BaseAddress = addr;
            this.MarkModified(1);
        }

        internal const char AddressPlaceholderSymbol = '*';
        internal const string AddressPlaceholderString = "*";

        private static string PreProcessNameFromIDA(string n, long addr)
        {
            if (string.IsNullOrEmpty(n))
                return n;

            string hex = addr.ToString("X");
            if (n.Length > hex.Length && n.EndsWith(hex, StringComparison.OrdinalIgnoreCase))
            {
                n = n.Substring(0, n.Length - hex.Length);
                n = n + AddressPlaceholderString;
            }

            return n;
        }

        private static string PreProcessNameToIDA(string n, long addr)
        {
            if (string.IsNullOrEmpty(n))
                return n;

            int ix;
            while((ix = n.IndexOf('*')) >= 0)
            {
                n = n.Remove(ix, 1);
                n = n.Insert(ix, addr.ToString("X"));
            }

            return n;
        }

        private void button8_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("A database must be loaded!");

                return;
            }

            if (Manager.CurrentDatabase.Versions == null || Manager.CurrentDatabase.Versions.Count == 0)
            {
                MessageBox.Show("A library version must be created to import names!");

                return;
            }

            var version = AskVersion(Manager.CurrentDatabase.Versions.Keys, "Select the version of the IDA database");

            if (!version.HasValue)
            {
                return;
            }

            Library library;

            if (!Manager.CurrentDatabase.Versions.TryGetValue(version.Value, out library))
            {
                MessageBox.Show("Something went wrong.");

                return;
            }

            var existingNamesList = GetExistingNames();

            var openFileDialogue = new OpenFileDialog();
            openFileDialogue.AddExtension = true;
            openFileDialogue.DefaultExt = "txt";
            openFileDialogue.CheckFileExists = true;
            openFileDialogue.Title = "Select idanames.txt";

            var openFileDialogueResult = openFileDialogue.ShowDialog();

            if (openFileDialogueResult != DialogResult.OK)
            {
                return;
            }

            try
            {
                var idNameDictionary = Manager.CurrentDatabase.Names;

                if (idNameDictionary == null)
                {
                    idNameDictionary = new SortedDictionary<ulong, string>();
                }

                int missingId = 0;
                int changedId = 0;

                var offsetIdDictionary = new Dictionary<uint, ulong>();

                if (library.Values != null)
                {
                    foreach (var idOffsetPair in library.Values)
                    {
                        offsetIdDictionary[idOffsetPair.Value] = idOffsetPair.Key;
                    }
                }

                var fileInfo = new System.IO.FileInfo(openFileDialogue.FileName);

                using (var streamReader = new System.IO.StreamReader(fileInfo.FullName))
                {
                    string line;
                    int lineNumber = 0;

                    while ((line = streamReader.ReadLine()) != null)
                    {
                        lineNumber++;

                        if (line.Length == 0)
                        {
                            continue;
                        }

                        var splitLine = line.Split(new[] { '\t' }, StringSplitOptions.None);

                        if (splitLine.Length != 3)
                        {
                            throw new FormatException("Invalid format on line " + lineNumber + ": " + line);
                        }

                        long address;

                        if (!long.TryParse(splitLine[0], System.Globalization.NumberStyles.AllowHexSpecifier, null, out address))
                        {
                            throw new FormatException("Invalid format on line " + lineNumber + ": " + line);
                        }

                        long offset = address - library.BaseAddress;

                        if (offset < 0 || offset > 0x40000000)
                        {
                            throw new FormatException("Address out of bounds on line " + lineNumber + ": " + address);
                        }

                        ulong id;
                        offsetIdDictionary.TryGetValue((uint)offset, out id);

                        if (id == 0)
                        {
                            missingId++;

                            continue;
                        }

                        string name = splitLine[1];
                        //if (!string.IsNullOrEmpty(splitLine[2])) { name = splitLine[2]; }
                        name = PreProcessNameFromIDA(name, address);

                        if (IsExistingName(existingNamesList, id, name))
                        {
                            continue;
                        }

                        string previousName;

                        if (!idNameDictionary.TryGetValue(id, out previousName) || previousName != name)
                        {
                            idNameDictionary[id] = name;
                            changedId++;
                        }
                    }
                }

                if (changedId > 0)
                {
                    this.MarkModified(2);
                }

                if (idNameDictionary.Count != 0)
                {
                    Manager.CurrentDatabase.Names = idNameDictionary;
                }

                string missingIdErrorMessage = "";

                if (missingId > 0)
                {
                    missingIdErrorMessage = " Unable to edit " + missingId + " names because the IDs were missing!";
                }

                MessageBox.Show("Modified " + changedId + " names." + missingIdErrorMessage);
            }
            catch (Exception exception)
            {
                ReportError(exception);
            }
        }

        private void button9_Click(object sender, EventArgs e)
        {
            StringBuilder str = new StringBuilder();
            str.AppendLine("0. [Edit the script IDAExportNames.py and change GetFilePath to where you want to export the names]");
            str.AppendLine("1. Run the script IDAExportNames.py");
            str.AppendLine("2. Click 'Import from IDA script result' button");
            str.AppendLine("3. Select version of binary you have open in IDA");
            str.AppendLine("4. Select the file idanames.txt");
            str.AppendLine("5. Wait for it to finish, names should be updated now");
            MessageBox.Show(str.ToString());
        }

        private void button10_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("You must load the database first!");
                return;
            }
            
            var all = AskNames(Manager.CurrentDatabase.Names, "Edit names manually");
            if (all == null)
                return;

            Manager.CurrentDatabase.Names = all;
            this.MarkModified(2);
        }

        private List<Dictionary<ulong, string>> GetExistingNames()
        {
            List<Dictionary<ulong, string>> existingNamesList = null;

            var messageBoxResult = MessageBox.Show(
                "Do you only want to write names that have changed? If so, names will be compared against the base idanames.txt files provided for each version in the Names subdirectory.",
                "Question",
                MessageBoxButtons.YesNo);

            if (messageBoxResult != DialogResult.Yes)
            {
                return existingNamesList;
            }

            existingNamesList = new List<Dictionary<ulong, string>>();

            var namesDirectory = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "Names");

            if (!System.IO.Directory.Exists(namesDirectory))
            {
                return existingNamesList;
            }

            foreach (var version in Manager.CurrentDatabase.Versions)
            {
                var versionDirectory = System.IO.Path.Combine(namesDirectory, version.Key.ToString());

                if (!System.IO.Directory.Exists(versionDirectory))
                {
                    continue;
                }

                var library = version.Value;
                var offsetIdDictionary = new Dictionary<uint, ulong>();

                if (library.Values != null)
                {
                    foreach (var idOffsetPair in library.Values)
                    {
                        offsetIdDictionary[idOffsetPair.Value] = idOffsetPair.Key;
                    }
                }

                foreach (var fileName in System.IO.Directory.GetFiles(versionDirectory))
                {
                    if (!System.IO.Path.GetExtension(fileName).Equals(".txt", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    try
                    {
                        var existingNames = new Dictionary<ulong, string>();

                        using (var streamReader = new System.IO.StreamReader(fileName))
                        {
                            string line;

                            while ((line = streamReader.ReadLine()) != null)
                            {
                                if (line.Length == 0)
                                {
                                    continue;
                                }

                                var splitLine = line.Split(new[] { '\t' }, StringSplitOptions.None);

                                if (splitLine.Length != 3)
                                {
                                    continue;
                                }

                                long address;

                                if (!long.TryParse(splitLine[0], System.Globalization.NumberStyles.AllowHexSpecifier, null, out address))
                                {
                                    continue;
                                }

                                long offset = address - library.BaseAddress;

                                if (offset < 0 || offset > 0x40000000)
                                {
                                    continue;
                                }

                                ulong id;
                                offsetIdDictionary.TryGetValue((uint)offset, out id);

                                if (id == 0)
                                {
                                    continue;
                                }

                                string name = splitLine[1];
                                //if (!string.IsNullOrEmpty(splitLine[2])) { name = splitLine[2]; }
                                name = PreProcessNameFromIDA(name, address);

                                if (!string.IsNullOrEmpty(name))
                                {
                                    existingNames[id] = name;
                                }
                            }
                        }

                        existingNamesList.Add(existingNames);
                    }
                    catch (Exception exception)
                    {
                        ReportError(exception);
                    }
                }
            }

            return existingNamesList;
        }

        private bool IsExistingName(List<Dictionary<ulong, string>> existingNamesList, ulong id, string name)
        {
            if (existingNamesList != null)
            {
                foreach (var existingNames in existingNamesList)
                {
                    if (existingNames != null)
                    {
                        string existingName;

                        if (existingNames.TryGetValue(id, out existingName) && existingName == name)
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private void WriteIDANames(bool ida7)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("A database must be loaded!");

                return;
            }

            if (Manager.CurrentDatabase.Names == null || Manager.CurrentDatabase.Names.Count == 0)
            {
                MessageBox.Show("No names are defined to export!");

                return;
            }

            if (Manager.CurrentDatabase.Versions == null || Manager.CurrentDatabase.Versions.Count == 0)
            {
                MessageBox.Show("A library version must be created to export names!");

                return;
            }

            var version = AskVersion(Manager.CurrentDatabase.Versions.Keys, "Select the version of the IDA database");

            if (!version.HasValue)
            {
                return;
            }

            Library library;

            if (!Manager.CurrentDatabase.Versions.TryGetValue(version.Value, out library))
            {
                MessageBox.Show("Something went wrong.");

                return;
            }

            if (library.Values == null || library.Values.Count == 0)
            {
                MessageBox.Show("No offsets are defined to export!");

                return;
            }

            var existingNamesList = GetExistingNames();

            try
            {
                int missingId = 0;
                int writeId = 0;

                var fileInfo = new System.IO.FileInfo("SetNamesInIDA.py");

                using (var streamWriter = new System.IO.StreamWriter(fileInfo.FullName, false, new UTF8Encoding(false)))
                {
                    streamWriter.WriteLine("def NameAddr(ea, name):");

                    if (!ida7)
                    {
                        streamWriter.WriteLine("    idc.MakeName(ea, name)");
                    }
                    else
                    {
                        streamWriter.WriteLine("    idc.set_name(ea, name, SN_CHECK)");
                    }

                    streamWriter.WriteLine();
                    streamWriter.WriteLine("print (\"Importing names...\")");
                    streamWriter.WriteLine();

                    foreach (var idNamePair in Manager.CurrentDatabase.Names)
                    {
                        string name = (idNamePair.Value ?? "");

                        if (name.Length == 0)
                        {
                            continue;
                        }

                        uint offset;

                        if (!library.Values.TryGetValue(idNamePair.Key, out offset))
                        {
                            missingId++;

                            continue;
                        }

                        if (IsExistingName(existingNamesList, idNamePair.Key, name))
                        {
                            continue;
                        }

                        long address = library.BaseAddress + offset;

                        name = PreProcessNameToIDA(name, address);
                        name = name.Replace("\"", "\\\"");

                        streamWriter.Write("NameAddr(0x");
                        streamWriter.Write(address.ToString("X"));
                        streamWriter.Write(", \"");
                        streamWriter.Write(name);
                        streamWriter.Write("\")");
                        streamWriter.WriteLine();

                        writeId++;
                    }

                    streamWriter.WriteLine();
                    streamWriter.WriteLine("print (\"Done with name import\")");
                }

                string statistics = writeId + " names have been written.";

                if (missingId > 0)
                {
                    statistics += " Failed to write " + missingId + " names because their IDs were not found.";
                }

                MessageBox.Show(statistics + Environment.NewLine + "The file " + fileInfo.Name + " has been written to " + fileInfo.DirectoryName + "!" + Environment.NewLine + "Run this script in IDA to set names.");
            }
            catch (Exception exception)
            {
                ReportError(exception);
            }
        }

        private void button11_Click(object sender, EventArgs e)
        {
            this.WriteIDANames(false);
        }

        private void button12_Click(object sender, EventArgs e)
        {
            this.WriteIDANames(true);
        }

        private void createNewVersionForMultiplePlatformsAndDoCrossdiffImportFromIDADiffCalculatorResultsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var f = new MultiImport();
            if (f.ShowDialog() != DialogResult.OK)
                return;

            this.MarkModified(1);
        }

        private sealed class wronginfo
        {
            internal long[] Address = new long[4];
            internal string Text;
        }

        private static string PreprocessName(string input)
        {
            int index;
            while ((index = input.IndexOf("lambda_")) >= 0)
            {
                int end = index + 7;
                while (end < input.Length)
                {
                    char ch = input[end];
                    if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))
                    {
                        end++;
                        continue;
                    }
                    break;
                }

                input = input.Remove(index, end - index);
                input = input.Insert(index, "LMBDA_REPLACED");
            }

            if (input.Length != 0 && input[0] == 'a')
            {
                bool did = false;
                int end = input.Length - 1;
                while (end >= 0)
                {
                    char ch = input[end];
                    if (ch >= '0' && ch <= '9')
                    {
                        end--;
                        continue;
                    }

                    if(ch == '_')
                    {
                        if (end == input.Length - 1)
                            break;

                        input = input.Substring(0, end);
                        did = true;
                        break;
                    }

                    break;
                }

                if(!did && (input.Length == 15 || input.Length == 14))
                    input = input.Substring(0, 13);
            }

            if (input.StartsWith("nullsub_"))
                return "nullsub";

            return input;
        }

        private void iDSanityCheckToolStripMenuItem_Click(object sender, EventArgs e)
        {
            var db = Manager.CurrentDatabase;
            if(db == null)
            {
                MessageBox.Show("Load database first!");
                return;
            }

            var first = AskVersion(db.Versions.Keys, "Select first version");
            if (!first.HasValue)
                return;

            var second = AskVersion(db.Versions.Keys, "Select second version");
            if (!second.HasValue)
                return;

            if(first.Value.Equals(second.Value))
            {
                MessageBox.Show("These are just two of the same version!");
                return;
            }

            var of = new OpenFileDialog();
            of.AddExtension = true;
            of.CheckFileExists = true;
            of.DefaultExt = "txt";
            of.Multiselect = false;
            of.Title = "Select idaexport_name.txt of " + first.Value.ToString() + " export";

            var r = of.ShowDialog();
            if (r != DialogResult.OK)
                return;

            var afi = new FileInfo(of.FileName);

            of = new OpenFileDialog();
            of.AddExtension = true;
            of.CheckFileExists = true;
            of.DefaultExt = "txt";
            of.Multiselect = false;
            of.Title = "Select idaexport_name.txt of " + second.Value.ToString() + " export";

            r = of.ShowDialog();
            if (r != DialogResult.OK)
                return;

            var bfi = new FileInfo(of.FileName);

            Dictionary<string, uint> amap = new Dictionary<string, uint>();
            Dictionary<string, uint> bmap = new Dictionary<string, uint>();

            try
            {
                using(var f = afi.OpenText())
                {
                    string l;
                    l = f.ReadLine();
                    if (l == null)
                        throw new FormatException();

                    var spl = l.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (spl.Length != 2 || spl[0] != "version")
                        throw new FormatException();

                    long addr = db.Versions[first.Value].BaseAddress;

                    while((l = f.ReadLine()) != null)
                    {
                        if (l.Length == 0)
                            continue;

                        spl = l.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (spl.Length < 3 || spl[0] != "name")
                            throw new FormatException();

                        long n;
                        if (!long.TryParse(spl[1], System.Globalization.NumberStyles.AllowHexSpecifier, null, out n) || n < 0)
                            throw new FormatException();

                        n -= addr;
                        if (n < 0 || n >= uint.MaxValue)
                            throw new FormatException();

                        string t = spl[2];
                        t = PreprocessName(t);

                        uint prev;
                        if (amap.TryGetValue(t, out prev))
                        {
                            if (prev != uint.MaxValue)
                                amap[t] = uint.MaxValue;
                        }
                        else
                            amap[t] = (uint)n;
                    }
                }

                using (var f = bfi.OpenText())
                {
                    string l;
                    l = f.ReadLine();
                    if (l == null)
                        throw new FormatException();

                    var spl = l.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (spl.Length != 2 || spl[0] != "version")
                        throw new FormatException();

                    long addr = db.Versions[second.Value].BaseAddress;

                    while ((l = f.ReadLine()) != null)
                    {
                        if (l.Length == 0)
                            continue;

                        spl = l.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (spl.Length < 3 || spl[0] != "name")
                            throw new FormatException();

                        long n;
                        if (!long.TryParse(spl[1], System.Globalization.NumberStyles.AllowHexSpecifier, null, out n) || n < 0)
                            throw new FormatException();

                        n -= addr;
                        if (n < 0 || n >= uint.MaxValue)
                            throw new FormatException();

                        string t = spl[2];
                        t = PreprocessName(t);

                        uint prev;
                        if (bmap.TryGetValue(t, out prev))
                        {
                            if (prev != uint.MaxValue)
                                bmap[t] = uint.MaxValue;
                        }
                        else
                            bmap[t] = (uint)n;
                    }
                }

                int didnt_check = 0;
                int correct = 0;
                int wrong = 0;
                int total = 0;
                int unmatched = 0;

                var alib = db.Versions[first.Value];
                var blib = db.Versions[second.Value];

                Dictionary<uint, ulong> alookup = new Dictionary<uint, ulong>();
                Dictionary<uint, ulong> blookup = new Dictionary<uint, ulong>();

                if(alib.Values != null)
                {
                    foreach (var pair in alib.Values)
                        alookup[pair.Value] = pair.Key;
                }

                if(blib.Values != null)
                {
                    foreach (var pair in blib.Values)
                        blookup[pair.Value] = pair.Key;
                }

                var examples = new List<wronginfo>();

                foreach(var pair in amap)
                {
                    uint av = pair.Value;
                    uint bv;

                    if(av == uint.MaxValue || !bmap.TryGetValue(pair.Key, out bv) || bv == uint.MaxValue)
                    {
                        didnt_check++;
                        continue;
                    }

                    ulong aid = 0;
                    ulong bid = 0;

                    alookup.TryGetValue(av, out aid);
                    blookup.TryGetValue(bv, out bid);

                    if(aid == 0 && bid == 0)
                    {
                        didnt_check++;
                        continue;
                    }

                    if(aid == 0 || bid == 0)
                    {
                        unmatched++;
                        total++;
                        continue;
                    }

                    if (aid != bid)
                    {
                        uint cv = 0;
                        blib.Values.TryGetValue(aid, out cv);
                        var info = new wronginfo();
                        info.Text = pair.Key;
                        info.Address[0] = av + alib.BaseAddress;
                        info.Address[1] = bv + blib.BaseAddress;
                        if(cv != 0)
                            info.Address[2] = cv + blib.BaseAddress;
                        alib.Values.TryGetValue(bid, out cv);
                        if(cv != 0)
                            info.Address[3] = cv + alib.BaseAddress;
                        if (info.Address[2] != 0 || info.Address[3] != 0)
                        {
                            wrong++;
                            examples.Add(info);
                        }
                        else
                            unmatched++;
                    }
                    else
                        correct++;
                    total++;
                }

                foreach(var pair in bmap)
                {
                    if (amap.ContainsKey(pair.Key))
                        continue;

                    didnt_check++;
                }

                var some_examples = new List<wronginfo>();
                var rnd = new Random();
                while(some_examples.Count < 20 && examples.Count != 0)
                {
                    int ri = rnd.Next(0, examples.Count);
                    var v = examples[ri];
                    examples.RemoveAt(ri);
                    some_examples.Add(v);
                }

                var bld = new StringBuilder();
                bld.AppendLine("Sanity checked version " + first.Value.ToString() + " to " + second.Value.ToString() + ":");
                bld.AppendLine();
                bld.AppendLine("Total: " + total);
                if (total > 0)
                {
                    bld.AppendLine("Correct: " + correct + " (" + ((double)correct * 100.0 / (double)total).ToString("0.####") + "%)");
                    bld.AppendLine("Unmatched: " + unmatched + " (" + ((double)unmatched * 100.0 / (double)total).ToString("0.####") + "%)");
                    bld.AppendLine("Wrong: " + wrong + " (" + ((double)wrong * 100.0 / (double)total).ToString("0.####") + "%)");
                }
                bld.AppendLine("Didn't check: " + didnt_check);

                if(some_examples.Count != 0)
                {
                    bld.AppendLine();
                    bld.AppendLine("Some examples of wrong:");
                    foreach(var pair in some_examples)
                    {
                        var str = new StringBuilder();
                        str.Append(pair.Address[0].ToString("X"));
                        str.Append(" -> ");
                        str.Append(pair.Address[1].ToString("X"));
                        str.Append(" | ");
                        str.Append(pair.Address[3].ToString("X"));
                        str.Append(" <- ");
                        str.Append(pair.Address[2].ToString("X"));
                        str.Append(" | ");
                        str.Append(pair.Text);
                        bld.AppendLine(str.ToString());
                    }
                }
                MessageBox.Show(bld.ToString());
            }
            catch(Exception ex)
            {
                ReportError(ex);
                return;
            }
        }
    }
}
