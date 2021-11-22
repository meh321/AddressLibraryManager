﻿using System;
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
                            all.AddNew(new _loadHelper._loadEntry() { Prev = pair.Value, Next = uint.MaxValue, Id = pair.Key });
                    }
                    if(next_lib.Values != null)
                    {
                        foreach(var pair in next_lib.Values)
                        {
                            var v = all.GetId(pair.Key);
                            if (v == null)
                                all.AddNew(new _loadHelper._loadEntry() { Prev = uint.MaxValue, Next = pair.Value, Id = pair.Key });
                            else
                            {
                                all.Remove(v);
                                v.Next = pair.Value;
                                all.AddNew(v);
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
                                    all.Remove(v);
                                    v.Next = xb;
                                    all.AddNew(v);
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
                                        all.Remove(v);
                                        v.Prev = xa;
                                        all.AddNew(v);
                                    }
                                }
                                else
                                    all.AddNew(new _loadHelper._loadEntry() { Prev = xa, Next = xb, Id = 0 });
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
                                all.AddNew(new _loadHelper._loadEntry() { Prev = xa, Next = uint.MaxValue, Id = 0 });
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
                                all.AddNew(new _loadHelper._loadEntry() { Prev = uint.MaxValue, Next = xa, Id = 0 });
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

            internal void AddNew(_loadEntry e)
            {
                if (e.Prev != uint.MaxValue)
                    this.MapPrev[e.Prev] = e;
                if (e.Next != uint.MaxValue)
                    this.MapNext[e.Next] = e;
                if (e.Id != 0)
                    this.MapId[e.Id] = e;
                this.All.Add(e);
            }

            internal void Remove(_loadEntry e)
            {
                if (e.Prev != uint.MaxValue)
                    this.MapPrev.Remove(e.Prev);
                if (e.Next != uint.MaxValue)
                    this.MapNext.Remove(e.Next);
                if (e.Id != 0)
                    this.MapId.Remove(e.Id);
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
                var fi = new System.IO.FileInfo("offsets.txt");
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

                MessageBox.Show("Wrote offsets.txt to " + fi.DirectoryName + "!");
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

            string has = this.textBox4.Text;
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

        private void button8_Click(object sender, EventArgs e)
        {
            if(Manager.CurrentDatabase == null)
            {
                MessageBox.Show("Must load a database first!");
                return;
            }

            if(Manager.CurrentDatabase.Versions == null || Manager.CurrentDatabase.Versions.Count == 0)
            {
                MessageBox.Show("Can't import names, there are no library versions created!");
                return;
            }

            var ver = AskVersion(Manager.CurrentDatabase.Versions.Keys, "Select version of IDA database");
            if (!ver.HasValue)
                return;

            Library lib;
            if(!Manager.CurrentDatabase.Versions.TryGetValue(ver.Value, out lib))
            {
                MessageBox.Show("Something went wrong.");
                return;
            }

            var of = new OpenFileDialog();
            of.AddExtension = true;
            of.DefaultExt = "txt";
            of.CheckFileExists = true;
            of.Title = "Select idanames.txt";

            var r = of.ShowDialog();
            if (r != DialogResult.OK)
                return;

            try
            {
                var map = Manager.CurrentDatabase.Names;
                if (map == null)
                    map = new SortedDictionary<ulong, string>();

                int missingId = 0;
                int changedId = 0;
                Dictionary<uint, ulong> revv = new Dictionary<uint, ulong>();
                if(lib.Values != null)
                {
                    foreach (var pair in lib.Values)
                        revv[pair.Value] = pair.Key;
                }
                var fi = new System.IO.FileInfo(of.FileName);
                using (var f = new System.IO.StreamReader(fi.FullName))
                {
                    string l;
                    int nr = 0;
                    while((l = f.ReadLine()) != null)
                    {
                        nr++;
                        if (l.Length == 0)
                            continue;

                        var spl = l.Split(new[] { '\t' }, StringSplitOptions.None);
                        if(spl.Length != 3)
                            throw new FormatException("Invalid format on line " + nr + ": " + l);

                        long addr;
                        if(!long.TryParse(spl[0], System.Globalization.NumberStyles.AllowHexSpecifier, null, out addr))
                            throw new FormatException("Invalid format on line " + nr + ": " + l);

                        long offset = addr - lib.BaseAddress;
                        if (offset < 0 || offset > 0x40000000)
                            throw new FormatException("Bad address on line " + nr + ": " + addr);

                        ulong id;
                        revv.TryGetValue((uint)offset, out id);

                        if(id == 0)
                        {
                            missingId++;
                            continue;
                        }

                        string n = spl[1];
                        //if (!string.IsNullOrEmpty(spl[2])) n = spl[2];
                        string prev;
                        if(!map.TryGetValue(id, out prev) || prev != n)
                        {
                            map[id] = n;
                            changedId++;
                        }
                    }
                }

                if(changedId > 0)
                    this.MarkModified(2);

                if (map.Count != 0)
                    Manager.CurrentDatabase.Names = map;

                string errorc = "";
                if (missingId > 0)
                    errorc = string.Format(" Unable to edit {0} names because the IDs were missing!", missingId);
                MessageBox.Show("Modified " + changedId + " names." + errorc);
            }
            catch(Exception ex)
            {
                ReportError(ex);
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

        private void button11_Click(object sender, EventArgs e)
        {
            if (Manager.CurrentDatabase == null)
            {
                MessageBox.Show("You must load the database first!");
                return;
            }

            if (Manager.CurrentDatabase.Names == null || Manager.CurrentDatabase.Names.Count == 0)
            {
                MessageBox.Show("There are no names defined, nothing to export.");
                return;
            }

            if(Manager.CurrentDatabase.Versions == null || Manager.CurrentDatabase.Versions.Count == 0)
            {
                MessageBox.Show("There are no versions defined, unable to calculate offsets!");
                return;
            }

            var ver = AskVersion(Manager.CurrentDatabase.Versions.Keys, "Select version in IDA");
            if (!ver.HasValue)
                return;

            Library lib;
            if(!Manager.CurrentDatabase.Versions.TryGetValue(ver.Value, out lib))
            {
                MessageBox.Show("Something went wrong.");
                return;
            }

            if (lib.Values == null || lib.Values.Count == 0)
            {
                MessageBox.Show("That version doesn't have any offsets defined, unable to export!");
                return;
            }

            var onlyChanged = MessageBox.Show("Do you only want to write names that have changed? If you click yes then you will be asked for idanames.txt file, and only names that are different from that file will be exported.", "Question", MessageBoxButtons.YesNoCancel);
            if (onlyChanged == DialogResult.Cancel)
                return;

            Dictionary<long, string> already = null;
            if(onlyChanged == DialogResult.Yes)
            {
                already = new Dictionary<long, string>();

                var of = new OpenFileDialog();
                of.AddExtension = true;
                of.DefaultExt = "txt";
                of.CheckFileExists = true;
                of.Title = "Select idanames.txt";

                var r = of.ShowDialog();
                if (r != DialogResult.OK)
                    return;

                try
                {
                    using (var swp = new System.IO.StreamReader(of.FileName))
                    {
                        string l;
                        while((l = swp.ReadLine()) != null)
                        {
                            if (l.Length == 0)
                                continue;

                            var spl = l.Split(new[] { '\t' }, StringSplitOptions.None);
                            if (spl.Length != 3)
                                continue;

                            long addr;
                            if (!long.TryParse(spl[0], System.Globalization.NumberStyles.AllowHexSpecifier, null, out addr))
                                continue;

                            string n = spl[1];
                            //if (!string.IsNullOrEmpty(spl[2])) n = spl[2];

                            if (!string.IsNullOrEmpty(n))
                                already[addr] = n;
                        }
                    }
                }
                catch(Exception ex)
                {
                    ReportError(ex);
                }
            }

            try
            {
                int missingId = 0;
                int writeId = 0;

                var fi = new System.IO.FileInfo("SetNamesInIDA.py");
                using (var sw = new System.IO.StreamWriter(fi.FullName, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("def NameAddr(ea, name):");
                    sw.WriteLine("    idc.MakeName(ea, name)");
                    sw.WriteLine();
                    sw.WriteLine("print \"Importing names...\"");
                    sw.WriteLine();
                    foreach(var pair in Manager.CurrentDatabase.Names)
                    {
                        string n = (pair.Value ?? "");
                        if (n.Length == 0)
                            continue;

                        uint offset;
                        if(!lib.Values.TryGetValue(pair.Key, out offset))
                        {
                            missingId++;
                            continue;
                        }

                        long addr = lib.BaseAddress + offset;
                        if(already != null)
                        {
                            string prev;
                            if (already.TryGetValue(addr, out prev) && prev == n)
                                continue;
                        }

                        n = n.Replace("\"", "\\\"");

                        sw.Write("NameAddr(0x");
                        sw.Write(addr.ToString("X"));
                        sw.Write(", \"");
                        sw.Write(n);
                        sw.Write("\")");
                        sw.WriteLine();
                        writeId++;
                    }

                    sw.WriteLine();
                    sw.WriteLine("print \"Done with name import\"");
                }

                string stats = "Wrote " + writeId + " renames.";
                if (missingId > 0)
                    stats += " Failed to write " + missingId + " because the IDs were not found.";
                MessageBox.Show(stats + Environment.NewLine + "Wrote file " + fi.Name + " to " + fi.DirectoryName + "!" + Environment.NewLine + "Run this as a script file in IDA.");
            }
            catch(Exception ex)
            {
                ReportError(ex);
            }
        }
    }
}