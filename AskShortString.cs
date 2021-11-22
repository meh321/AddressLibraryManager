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
    public partial class AskShortString : Form
    {
        public AskShortString()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void textBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if(e.KeyCode == Keys.Enter)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                this.DialogResult = DialogResult.OK;
                this.Close();
                return;
            }

            if(e.KeyCode == Keys.Escape)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                this.Close();
                return;
            }
        }

        private void AskShortString_Load(object sender, EventArgs e)
        {
            this.textBox1.Select();
        }
    }
}
