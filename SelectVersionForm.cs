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
    public partial class SelectVersionForm : Form
    {
        public SelectVersionForm()
        {
            InitializeComponent();
        }

        internal List<Version> AllVersions;
        internal Version SelectedVersion;

        private void button1_Click(object sender, EventArgs e)
        {
            int ix = this.listBox1.SelectedIndex;
            if(ix < 0 || ix >= this.listBox1.Items.Count)
            {
                MessageBox.Show("You must select a version to continue! Close this window to abort.");
                return;
            }

            this.SelectedVersion = (Version)this.listBox1.Items[ix];
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void SelectVersionForm_Load(object sender, EventArgs e)
        {
            if(this.AllVersions != null && this.AllVersions.Count != 0)
            {
                foreach (var x in this.AllVersions)
                    this.listBox1.Items.Add(x);
            }
        }
    }
}
