// Internet Monitor - the window.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace InternetMonitor
{
    internal static class Theme
    {
        public static readonly Color Page = Color.FromArgb(0xF3, 0xF4, 0xF6);
        public static readonly Color Card = Color.White;
        public static readonly Color Header = Color.FromArgb(0x10, 0x28, 0x3F);
        public static readonly Color Ink = Color.FromArgb(0x0B, 0x0B, 0x0B);
        public static readonly Color Ink2 = Color.FromArgb(0x52, 0x51, 0x4E);
        public static readonly Color Muted = Color.FromArgb(0x89, 0x87, 0x81);
        public static readonly Color Grid = Color.FromArgb(0xE1, 0xE0, 0xD9);
        public static readonly Color Accent = Color.FromArgb(0x2A, 0x78, 0xD6);
        public static readonly Color Good = Color.FromArgb(0x0C, 0xA3, 0x0C);
        public static readonly Color Warning = Color.FromArgb(0xFA, 0xB2, 0x19);
        public static readonly Color Critical = Color.FromArgb(0xD0, 0x3B, 0x3B);
        public static readonly Color Idle = Color.FromArgb(0xC3, 0xC2, 0xB7);

        public static Color ForSeverity(int sev)
        {
            return sev == 0 ? Good : sev == 1 ? Warning : Critical;
        }
    }

    /// <summary>The round status light.</summary>
    internal sealed class StatusDot : Control
    {
        private Color color = Theme.Idle;
        public Color DotColor { get { return color; } set { color = value; Invalidate(); } }

        public StatusDot()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            e.Graphics.Clear(BackColor);
            Rectangle r = new Rectangle(1, 1, Width - 3, Height - 3);
            using (SolidBrush halo = new SolidBrush(Color.FromArgb(46, color))) e.Graphics.FillEllipse(halo, r);
            r.Inflate(-Width / 5, -Height / 5);
            using (SolidBrush b = new SolidBrush(color)) e.Graphics.FillEllipse(b, r);
        }
    }

    /// <summary>Rolling ten-minute chart of response time with problem periods shaded.</summary>
    internal sealed class LiveChart : Control
    {
        private struct Pt { public DateTime T; public int Sev; public int Ms; }
        private readonly List<Pt> points = new List<Pt>();
        private const int WindowSeconds = 600;
        public string IdleText = "Press Start to begin monitoring";

        public LiveChart()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Card;
        }

        public void Clear() { points.Clear(); Invalidate(); }

        public void Add(DateTime t, int sev, int ms)
        {
            Pt p = new Pt(); p.T = t; p.Sev = sev; p.Ms = ms;
            points.Add(p);
            DateTime cut = t.AddSeconds(-WindowSeconds - 30);
            int drop = 0;
            while (drop < points.Count && points[drop].T < cut) drop++;
            if (drop > 0) points.RemoveRange(0, drop);
            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            float k = g.DpiX / 96f;
            g.Clear(BackColor);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            float ml = 50 * k, mr = 8 * k, mt = 6 * k, mb = 20 * k;
            RectangleF plot = new RectangleF(ml, mt, Width - ml - mr, Height - mt - mb);
            if (plot.Width < 20 || plot.Height < 20) return;

            using (Font f = new Font("Segoe UI", 8f))
            using (SolidBrush muted = new SolidBrush(Theme.Muted))
            using (Pen grid = new Pen(Theme.Grid, 1f))
            {
                int max = 100;
                foreach (Pt p in points) { if (p.Ms > max) max = p.Ms; }
                int[] nice = { 100, 200, 400, 500, 1000, 2000, 4000, 5000, 10000, 20000, 40000 };
                int top = nice[nice.Length - 1];
                foreach (int nv in nice) { if (nv >= max) { top = nv; break; } }

                StringFormat right = new StringFormat(); right.Alignment = StringAlignment.Far; right.LineAlignment = StringAlignment.Center;
                for (int i = 0; i <= 4; i++)
                {
                    float y = plot.Bottom - plot.Height * i / 4f;
                    g.DrawLine(grid, plot.Left, y, plot.Right, y);
                    string label = (top * i / 4).ToString("N0") + (i == 4 ? " ms" : "");
                    g.DrawString(label, f, muted, new RectangleF(0, y - 8 * k, ml - 6 * k, 16 * k), right);
                }

                StringFormat centre = new StringFormat(); centre.Alignment = StringAlignment.Center;
                StringFormat far = new StringFormat(); far.Alignment = StringAlignment.Far;
                g.DrawString("10 min ago", f, muted, plot.Left, plot.Bottom + 3 * k);
                g.DrawString("5 min ago", f, muted, new RectangleF(plot.Left, plot.Bottom + 3 * k, plot.Width, 16 * k), centre);
                g.DrawString("now", f, muted, new RectangleF(plot.Left, plot.Bottom + 3 * k, plot.Width, 16 * k), far);

                if (points.Count == 0)
                {
                    StringFormat mid = new StringFormat(); mid.Alignment = StringAlignment.Center; mid.LineAlignment = StringAlignment.Center;
                    using (Font big = new Font("Segoe UI", 9.5f)) g.DrawString(IdleText, big, muted, plot, mid);
                    return;
                }

                DateTime now = points[points.Count - 1].T;
                DateTime start = now.AddSeconds(-WindowSeconds);
                Func<DateTime, float> X = delegate(DateTime t)
                {
                    double frac = (t - start).TotalSeconds / WindowSeconds;
                    return plot.Left + (float)(Math.Max(0, Math.Min(1, frac)) * plot.Width);
                };

                // shaded bands wherever the connection was not fully online
                for (int i = 0; i < points.Count; i++)
                {
                    if (points[i].Sev == 0) continue;
                    DateTime until = i + 1 < points.Count ? points[i + 1].T : now.AddSeconds(1);
                    float x0 = X(points[i].T), x1 = Math.Max(X(until), x0 + 2 * k);
                    if (x1 <= plot.Left) continue;
                    Color c = Theme.ForSeverity(points[i].Sev);
                    using (SolidBrush b = new SolidBrush(Color.FromArgb(points[i].Sev == 2 ? 70 : 90, c)))
                        g.FillRectangle(b, x0, plot.Top, x1 - x0, plot.Height);
                }

                // response-time line, broken where nothing answered
                using (Pen line = new Pen(Theme.Accent, 2f * k))
                {
                    line.LineJoin = LineJoin.Round; line.StartCap = LineCap.Round; line.EndCap = LineCap.Round;
                    List<PointF> run = new List<PointF>();
                    for (int i = 0; i <= points.Count; i++)
                    {
                        bool has = i < points.Count && points[i].Ms >= 0 && points[i].T >= start;
                        if (has)
                        {
                            float y = plot.Bottom - plot.Height * Math.Min(points[i].Ms, top) / (float)top;
                            run.Add(new PointF(X(points[i].T), y));
                        }
                        else if (run.Count > 0)
                        {
                            if (run.Count == 1) { using (SolidBrush b = new SolidBrush(Theme.Accent)) g.FillEllipse(b, run[0].X - 2 * k, run[0].Y - 2 * k, 4 * k, 4 * k); }
                            else g.DrawLines(line, run.ToArray());
                            run.Clear();
                        }
                    }
                }
            }
        }
    }

    internal sealed class MainForm : Form
    {
        private readonly Settings settings;
        private readonly LogStore store;
        private readonly string[] args;
        private Engine engine;
        private bool closeWhenStopped;
        private string lastReportPath;

        private StatusDot dot;
        private Label lblStatus, lblExplain, lblElapsed, lblIp;
        private Label tileAvail, tileOutages, tileDown, tileDeg, tileDegCaption, tileResp, tileRespCaption;
        private LiveChart chart;
        private Label lblWifi;
        private ListView list;
        private ComboBox cboInterval, cboDuration, cboAdapter;
        private readonly List<string> adapterIds = new List<string>();   // one per cboAdapter item; "" = automatic
        private CheckBox chkAwake;
        private Button btnStart, btnReport, btnFolder;
        private Label lblFooter;
        private ContextMenuStrip reportMenu;
        private Timer clock;

        private static readonly int[] IntervalValues = { 0, 1000, 2000, 5000, 10000, 30000, 60000 };
        private static readonly string[] IntervalNames =
        {
            "Adaptive: 5 s, speeding up to 1 s during problems (recommended)",
            "Every second (short tests only)", "Every 2 seconds", "Every 5 seconds", "Every 10 seconds", "Every 30 seconds", "Every minute"
        };
        private static int[] DurationValues = { 0, 15, 60, 240, 480, 1440, 10080 };
        private static readonly string[] DurationNames =
        {
            "Until I press Stop", "15 minutes", "1 hour", "4 hours", "8 hours", "24 hours", "7 days"
        };

        public MainForm(Settings settings, LogStore store, string[] args)
        {
            this.settings = settings;
            this.store = store;
            this.args = args;
            BuildUi();
            ShowIdle();
        }

        // ------------------------------------------------------------------ layout
        private void BuildUi()
        {
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = AppInfo.Name;
            Font = new Font("Segoe UI", 9f);
            BackColor = Theme.Page;
            ForeColor = Theme.Ink;
            ClientSize = new Size(760, 730);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            try
            {
                using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico")) { if (s != null) Icon = new Icon(s); }
            }
            catch { }

            // header band
            Panel header = new Panel();
            header.SetBounds(0, 0, 760, 56);
            header.BackColor = Theme.Header;
            Label title = MakeLabel(AppInfo.Name, 18, 7, 13f, true, Color.White, header);
            title.BackColor = Theme.Header;
            string sub = settings.Organisation.Length > 0 ? settings.Organisation : "Connection and proxy uptime monitor";
            Label subtitle = MakeLabel(sub, 20, 32, 8.5f, false, Color.FromArgb(0xB9, 0xC6, 0xD4), header);
            subtitle.BackColor = Theme.Header;
            lblElapsed = new Label();
            lblElapsed.AutoSize = false;
            lblElapsed.Width = 300;
            lblElapsed.Dock = DockStyle.Right;
            lblElapsed.Padding = new Padding(0, 0, 16, 0);
            lblElapsed.TextAlign = ContentAlignment.MiddleRight;
            lblElapsed.ForeColor = Color.FromArgb(0xB9, 0xC6, 0xD4);
            lblElapsed.BackColor = Theme.Header;
            lblElapsed.Text = "v" + AppInfo.Version;
            header.Controls.Add(lblElapsed);
            Controls.Add(header);

            // status card
            Panel status = MakeCard(16, 66, 728, 72);
            dot = new StatusDot();
            dot.SetBounds(16, 16, 40, 40);
            dot.BackColor = Theme.Card;
            status.Controls.Add(dot);
            lblStatus = MakeLabel("Ready", 68, 9, 15f, true, Theme.Ink, status);
            lblExplain = new Label();
            lblExplain.SetBounds(70, 40, 646, 30);
            lblExplain.ForeColor = Theme.Ink2;
            lblExplain.Font = new Font("Segoe UI", 8.5f);
            status.Controls.Add(lblExplain);
            // The address the rest of the internet sees this network as (top right of the status card).
            lblIp = new Label();
            lblIp.SetBounds(396, 12, 320, 18);
            lblIp.TextAlign = ContentAlignment.MiddleRight;
            lblIp.Font = new Font("Segoe UI", 8.5f);
            lblIp.ForeColor = Theme.Ink2;
            lblIp.BackColor = Theme.Card;
            lblIp.AutoEllipsis = true;
            status.Controls.Add(lblIp);

            // stat tiles
            int tw = 137, gap = 10;
            tileAvail = MakeTile(16 + 0 * (tw + gap), 148, tw, "Availability");
            tileOutages = MakeTile(16 + 1 * (tw + gap), 148, tw, "Outages");
            tileDown = MakeTile(16 + 2 * (tw + gap), 148, tw, "Downtime");
            tileDeg = MakeTile(16 + 3 * (tw + gap), 148, tw, "Degraded");
            tileDegCaption = (Label)tileDeg.Tag;
            tileResp = MakeTile(16 + 4 * (tw + gap), 148, tw + 3, "Response");
            tileRespCaption = (Label)tileResp.Tag;

            // live chart
            Panel chartCard = MakeCard(16, 220, 728, 108);
            MakeLabel("Web response time, last 10 minutes (shaded = problem detected)", 12, 6, 8.5f, false, Theme.Ink2, chartCard);
            lblWifi = new Label();
            lblWifi.SetBounds(400, 5, 320, 18);
            lblWifi.TextAlign = ContentAlignment.MiddleRight;
            lblWifi.Font = new Font("Segoe UI", 8.5f);
            lblWifi.ForeColor = Theme.Ink2;
            lblWifi.BackColor = Theme.Card;
            lblWifi.AutoEllipsis = true;
            chartCard.Controls.Add(lblWifi);
            chart = new LiveChart();
            chart.SetBounds(8, 26, 712, 78);
            chartCard.Controls.Add(chart);

            // checks list
            Panel listCard = MakeCard(16, 338, 728, 246);
            list = new ListView();
            list.SetBounds(6, 4, 716, 238);
            list.View = View.Details;
            list.FullRowSelect = true;
            list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            list.BorderStyle = BorderStyle.None;
            list.ShowItemToolTips = true;
            list.Columns.Add("Check", 166);
            list.Columns.Add("Based", 96);
            list.Columns.Add("Tests", 174);
            list.Columns.Add("Result", 152);
            list.Columns.Add("Time", 56, HorizontalAlignment.Right);
            list.Columns.Add("Success", 62, HorizontalAlignment.Right);
            typeof(Control).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(list, true, null);
            listCard.Controls.Add(list);

            // options (set before the run)
            // Which network connection to test. Matters on a computer with two (two lines, or wired plus Wi-Fi).
            Label l0 = MakeLabel("Network adapter", 16, 598, 9f, false, Theme.Ink2, this);
            l0.BackColor = Theme.Page;
            cboAdapter = MakeCombo(118, 594, 626, new string[0]);
            FillAdapters(NetInfo.Find(settings.Adapter));
            cboAdapter.DropDown += delegate { FillAdapters(null); };     // pick up anything plugged in since

            Label l1 = MakeLabel("Check frequency", 16, 632, 9f, false, Theme.Ink2, this);
            l1.BackColor = Theme.Page;
            cboInterval = MakeCombo(118, 628, 392, IntervalNames);
            Label l2 = MakeLabel("Run for", 524, 632, 9f, false, Theme.Ink2, this);
            l2.BackColor = Theme.Page;
            cboDuration = MakeCombo(576, 628, 168, DurationNames);

            int idx = 0;
            int ms;
            if (settings.DefaultInterval != "adaptive" && int.TryParse(settings.DefaultInterval, out ms))
                idx = Math.Max(0, Array.IndexOf(IntervalValues, ms * 1000));
            cboInterval.SelectedIndex = idx;
            cboDuration.SelectedIndex = Math.Max(0, Array.IndexOf(DurationValues, settings.DefaultDurationMinutes));

            chkAwake = new CheckBox();
            chkAwake.Text = "Keep this computer awake while monitoring";
            chkAwake.SetBounds(18, 670, 300, 24);
            chkAwake.Checked = settings.KeepAwake;
            chkAwake.ForeColor = Theme.Ink2;
            Controls.Add(chkAwake);

            btnFolder = MakeButton("Open folder", 368, 664, 112, false);
            btnFolder.Click += delegate { OpenPath(store.Root); };
            btnReport = MakeButton("View report  ▾", 488, 664, 122, false);
            btnReport.Click += delegate { reportMenu.Show(btnReport, new Point(0, btnReport.Height)); };
            btnStart = MakeButton("Start monitoring", 618, 664, 126, true);
            btnStart.Click += delegate { if (engine != null && engine.IsRunning) StopMonitoring(); else StartMonitoring(); };
            AcceptButton = btnStart;

            reportMenu = new ContextMenuStrip();
            reportMenu.Items.Add("This session", null, delegate { MakeReport("session", true); });
            reportMenu.Items.Add(new ToolStripSeparator());
            reportMenu.Items.Add("Today (from saved logs)", null, delegate { MakeReport("today", true); });
            reportMenu.Items.Add("Last 7 days (from saved logs)", null, delegate { MakeReport("7", true); });
            reportMenu.Items.Add("Last 30 days (from saved logs)", null, delegate { MakeReport("30", true); });
            reportMenu.Items.Add(new ToolStripSeparator());
            reportMenu.Items.Add("All computers: last 7 days (this data folder)", null, delegate { MakeCombined(store.LogDir, false, 7); });
            reportMenu.Items.Add("All computers: choose a folder\u2026", null, delegate
            {
                using (FolderBrowserDialog dlg = new FolderBrowserDialog())
                {
                    dlg.Description = "Choose the folder that holds the log files from several computers. "
                        + "Sub-folders are included; put each school or site in its own sub-folder.";
                    dlg.ShowNewFolderButton = false;
                    if (dlg.ShowDialog(this) == DialogResult.OK) MakeCombined(dlg.SelectedPath, true, 30);
                }
            });

            lblFooter = new Label();
            lblFooter.SetBounds(16, 706, 728, 18);
            lblFooter.ForeColor = Theme.Muted;
            lblFooter.Font = new Font("Segoe UI", 8f);
            lblFooter.AutoEllipsis = true;
            Controls.Add(lblFooter);

            clock = new Timer();
            clock.Interval = 1000;
            clock.Tick += delegate { UpdateElapsed(); };

            ResumeLayout(false);
            PerformAutoScale();

            // ListView column widths are not scaled automatically.
            float k;
            using (Graphics g = CreateGraphics()) k = g.DpiX / 96f;
            foreach (ColumnHeader c in list.Columns) c.Width = (int)(c.Width * k);

            // On a small or heavily scaled screen the window may not fit. Everything below the
            // list of checks is pinned to the bottom edge and the list gives up the space
            // (it scrolls), so the Start button can never end up off-screen.
            listCard.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
            list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
            foreach (Control c in new Control[] { l0, cboAdapter, l1, l2, cboInterval, cboDuration, chkAwake, btnFolder, btnReport, btnStart, lblFooter })
                c.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            int chrome = Height - ClientSize.Height;
            int room = Screen.FromPoint(Cursor.Position).WorkingArea.Height - chrome - (int)(8 * k);
            if (ClientSize.Height > room) ClientSize = new Size(ClientSize.Width, Math.Max(room, (int)(480 * k)));
        }

        /// <summary>
        /// Lists the adapters that have a route out (a default gateway). The current choice is
        /// kept across a refresh; "select" overrides it (settings file or command line).
        /// </summary>
        private void FillAdapters(NetInfo select)
        {
            string wanted = select != null ? select.Id
                : cboAdapter.SelectedIndex >= 0 && cboAdapter.SelectedIndex < adapterIds.Count ? adapterIds[cboAdapter.SelectedIndex] : "";
            List<NetInfo> all = NetInfo.All();
            NetInfo auto = NetInfo.Detect();

            cboAdapter.BeginUpdate();
            cboAdapter.Items.Clear();
            adapterIds.Clear();
            cboAdapter.Items.Add("Automatic: let Windows choose" + (auto.AdapterName.Length > 0 ? " (at the moment: " + auto.AdapterName + ")" : ""));
            adapterIds.Add("");
            foreach (NetInfo n in all)
            {
                if (n.Gateway == null && n.Id != wanted) continue;
                cboAdapter.Items.Add(n.AdapterName + "  ·  " + n.LocalIP + (n.Gateway != null ? "  ·  gateway " + n.Gateway : "  ·  no gateway")
                    + "  ·  " + n.Description);
                adapterIds.Add(n.Id);
            }
            int index = adapterIds.IndexOf(wanted);
            cboAdapter.SelectedIndex = index >= 0 ? index : 0;
            cboAdapter.EndUpdate();
        }

        private string SelectedAdapterId
        {
            get { return cboAdapter.SelectedIndex >= 0 && cboAdapter.SelectedIndex < adapterIds.Count ? adapterIds[cboAdapter.SelectedIndex] : ""; }
        }

        private Label MakeLabel(string text, int x, int y, float size, bool bold, Color color, Control parent)
        {
            Label l = new Label();
            l.AutoSize = true;
            l.Text = text;
            l.Location = new Point(x, y);
            l.Font = bold ? new Font("Segoe UI Semibold", size) : new Font("Segoe UI", size);
            l.ForeColor = color;
            l.BackColor = parent is Form ? Theme.Page : Theme.Card;
            parent.Controls.Add(l);
            return l;
        }

        private Panel MakeCard(int x, int y, int w, int h)
        {
            Panel p = new Panel();
            p.SetBounds(x, y, w, h);
            p.BackColor = Theme.Card;
            p.Paint += delegate(object s, PaintEventArgs e)
            {
                using (Pen pen = new Pen(Color.FromArgb(0xDD, 0xDF, 0xE3))) e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1);
            };
            Controls.Add(p);
            return p;
        }

        private Label MakeTile(int x, int y, int w, string caption)
        {
            Panel p = MakeCard(x, y, w, 62);
            Label cap = MakeLabel(caption, 11, 7, 8.5f, false, Theme.Ink2, p);
            Label val = MakeLabel("–", 9, 24, 15f, true, Theme.Ink, p);
            val.Tag = cap;
            return val;
        }

        private ComboBox MakeCombo(int x, int y, int w, string[] items)
        {
            ComboBox c = new ComboBox();
            c.DropDownStyle = ComboBoxStyle.DropDownList;
            c.SetBounds(x, y, w, 24);
            c.Items.AddRange(items);
            Controls.Add(c);
            return c;
        }

        private Button MakeButton(string text, int x, int y, int w, bool primary)
        {
            Button b = new Button();
            b.Text = text;
            b.SetBounds(x, y, w, 32);
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 1;
            b.Cursor = Cursors.Hand;
            StyleButton(b, primary);
            Controls.Add(b);
            return b;
        }

        private static void StyleButton(Button b, bool primary)
        {
            b.BackColor = primary ? Theme.Accent : Color.White;
            b.ForeColor = primary ? Color.White : Theme.Ink;
            b.FlatAppearance.BorderColor = primary ? Theme.Accent : Color.FromArgb(0xC3, 0xC6, 0xCC);
            b.Font = primary ? new Font("Segoe UI Semibold", 9f) : new Font("Segoe UI", 9f);
        }

        // ------------------------------------------------------------------ states
        private void ShowIdle()
        {
            dot.DotColor = Theme.Idle;
            lblStatus.Text = "Ready to monitor";
            lblExplain.Text = "Choose how often to check and for how long, then press Start. Leave this window open; a report is produced when you stop.";
            SetFooter();
            FillList(BuildPreviewSchema(), null);
            if (settings.Warnings.Count > 0) lblExplain.Text = "Settings file problem: " + settings.Warnings[0];
        }

        private void SetFooter()
        {
            string text = "Saving to " + store.Root;
            if (store.RootNote.Length > 0) text = store.RootNote + "  " + text;
            if (store.LastError != null) text = "Could not write the log file (" + store.LastError + "). Results are being kept in memory.";
            lblFooter.Text = text;
            lblFooter.ForeColor = store.LastError != null ? Theme.Critical : Theme.Muted;
        }

        private Schema BuildPreviewSchema()
        {
            return new Engine(settings, store, 0, 0, false).Schema;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            // Command-line switches for IT staff: /start /interval:5 /duration:60 /minimized
            bool start = false;
            foreach (string raw in args)
            {
                string a = raw.TrimStart('/', '-').ToLowerInvariant();
                int n;
                if (a == "start") start = true;
                else if (a == "minimized" || a == "minimised") WindowState = FormWindowState.Minimized;
                else if (a.StartsWith("adapter:"))
                {
                    // /adapter:"Ethernet 2"  or  /adapter:192.168.1.17  or  /adapter:auto
                    string v = raw.Substring(raw.IndexOf(':') + 1).Trim().Trim('"');
                    NetInfo found = NetInfo.Find(v);
                    if (found != null) FillAdapters(found);
                    else if (v.Equals("auto", StringComparison.OrdinalIgnoreCase)) cboAdapter.SelectedIndex = 0;
                    else adapterProblem = "The network adapter “" + v + "” was not found, so monitoring was not started.";
                }
                else if (a.StartsWith("interval:"))
                {
                    string v = a.Substring(9);
                    int i = v == "adaptive" ? 0 : (int.TryParse(v, out n) ? Array.IndexOf(IntervalValues, n * 1000) : -1);
                    if (i >= 0) cboInterval.SelectedIndex = i;
                }
                else if (a.StartsWith("duration:") && int.TryParse(a.Substring(9), out n))
                {
                    int i = Array.IndexOf(DurationValues, n);
                    if (i < 0 && n > 0)
                    {
                        // any other length of run, e.g. /duration:90
                        List<int> values = new List<int>(DurationValues);
                        values.Add(n);
                        DurationValues = values.ToArray();
                        i = cboDuration.Items.Add(n == 1 ? "1 minute" : n + " minutes");
                    }
                    if (i >= 0) cboDuration.SelectedIndex = i;
                }
            }
            // Never fall back silently to another line: that would produce a report about the wrong connection.
            if (adapterProblem == null && settings.Adapter.Length > 0 && NetInfo.Find(settings.Adapter) == null && SelectedAdapterId.Length == 0)
                adapterProblem = "The network adapter “" + settings.Adapter + "” named in InternetMonitor.ini was not found.";
            if (adapterProblem != null)
            {
                lblExplain.Text = adapterProblem + " Choose one under Network adapter, then press Start.";
                return;
            }
            if (start) StartMonitoring();
        }

        private string adapterProblem;

        private void StartMonitoring()
        {
            int interval = IntervalValues[cboInterval.SelectedIndex];
            int minutes = DurationValues[cboDuration.SelectedIndex];
            engine = new Engine(settings, store, interval, minutes, chkAwake.Checked, SelectedAdapterId);
            engine.SampleTaken += delegate(Sample s) { Post(delegate { OnSample(s); }); };
            engine.Stopped += delegate(bool timedOut) { Post(delegate { OnStopped(timedOut); }); };

            chart.Clear();
            chart.IdleText = "Running the first checks…";
            FillList(engine.Schema, null);
            tileAvail.Text = tileOutages.Text = tileDown.Text = tileDeg.Text = tileResp.Text = "–";
            tileDegCaption.Text = "Degraded";
            tileRespCaption.Text = "Response";
            lblIp.Text = "";
            dot.DotColor = Theme.Idle;
            lblStatus.Text = "Starting…";
            lblExplain.Text = "Running the first set of checks.";
            cboAdapter.Enabled = cboInterval.Enabled = cboDuration.Enabled = chkAwake.Enabled = false;
            btnStart.Text = "Stop monitoring";
            StyleButton(btnStart, false);
            lastReportPath = null;

            engine.Start();
            clock.Start();
            UpdateElapsed();
        }

        private void StopMonitoring()
        {
            if (engine == null) return;
            btnStart.Enabled = false;
            btnStart.Text = "Stopping…";
            engine.Stop();
        }

        private void Post(MethodInvoker action)
        {
            try { if (IsHandleCreated && !IsDisposed) BeginInvoke(action); } catch { }
        }

        private void UpdateElapsed()
        {
            if (engine == null) return;
            TimeSpan t = DateTime.Now - engine.Stats.Started;
            string running = string.Format("Running {0:00}:{1:00}:{2:00}", (int)t.TotalHours, t.Minutes, t.Seconds);
            if (engine.DurationMinutes > 0)
            {
                TimeSpan left = engine.Stats.Started.AddMinutes(engine.DurationMinutes) - DateTime.Now;
                if (left.TotalSeconds > 0) running += "  ·  " + ReportBuilder.Duration(left.TotalSeconds) + " left";
            }
            lblElapsed.Text = running;
        }

        // ------------------------------------------------------------------ live updates
        private void OnSample(Sample s)
        {
            if (engine == null) return;
            int sev = St.Severity(s.Status);
            dot.DotColor = Theme.ForSeverity(sev);
            lblStatus.Text = St.Label(s.Status);
            lblExplain.Text = s.Status == St.Degraded ? ExplainDegraded(s) : s.Status == St.Inspection ? ExplainInspection(s) : St.Explain(s.Status);
            Text = St.Label(s.Status) + " - " + AppInfo.Name;

            SessionStats st = engine.Stats;
            double avail, down, deg; int outages, degCount, last, avg;
            int[] tests, oks;
            lock (st)
            {
                avail = st.AvailabilityPct; down = st.TotalDownSec; outages = st.Outages; last = st.LastResponseMs;
                deg = st.TotalDegradedSec; degCount = st.DegradedEpisodes;
                avg = st.ResponseCount > 0 ? (int)(st.ResponseSum / st.ResponseCount) : -1;
                tests = (int[])st.CheckTests.Clone(); oks = (int[])st.CheckOk.Clone();
            }
            tileAvail.Text = avail >= 99.995 ? "100%" : avail.ToString("0.00") + "%";
            tileOutages.Text = outages.ToString();
            tileOutages.ForeColor = outages > 0 ? Theme.Critical : Theme.Ink;
            tileDown.Text = down < 0.5 ? "None" : ReportBuilder.Duration(down);
            // Degraded time still counts as available, so it gets a figure of its own.
            tileDeg.Text = degCount == 0 ? "None" : ReportBuilder.Duration(deg);
            tileDegCaption.Text = degCount == 0 ? "Degraded" : "Degraded (" + degCount + (degCount == 1 ? " time)" : " times)");
            tileResp.Text = last >= 0 ? last + " ms" : "–";
            tileRespCaption.Text = avg >= 0 ? "Response (avg " + avg + " ms)" : "Response";

            string ip = s.ExternalIP ?? "";
            int ipChanges = engine.ExternalIPChanges;
            lblIp.Text = ip.Length == 0 ? "Public IP not known yet"
                       : "Public IP  " + ip + (ipChanges > 0 ? "  (changed " + ipChanges + " times)" : "");

            chart.Add(s.Time, sev, last);
            lblWifi.Text = s.WifiBssid.Length > 0 ? "Wi-Fi " + s.WifiSignal + "%  \u00b7  AP " + s.WifiBssid
                         : s.WifiLinkMbps >= 0 ? "Wi-Fi link " + s.WifiLinkMbps + " Mbps" : "";
            FillList(s.Schema, s, tests, oks);
            SetFooter();
        }

        // Says which sites are affected and which are not, which is the whole argument in one line.
        private string ExplainInspection(Sample s)
        {
            List<string> failing = new List<string>(), working = new List<string>();
            for (int i = 0; i < s.Schema.Defs.Length; i++)
            {
                CheckDef d = s.Schema.Defs[i];
                if (d.Kind != "HTTP" || d.Service || !s.R[i].Tested) continue;
                if (engine != null && engine.IsHttpExcluded(i)) continue;
                if (s.R[i].Ok) working.Add(d.Name); else failing.Add(d.Name);
            }
            if (failing.Count == 0) return St.Explain(s.Status);
            return "The sites the web filter decrypts (" + string.Join(", ", failing.ToArray()) + ") are not loading, while "
                + (working.Count > 0 ? "the ones it leaves alone (" + string.Join(", ", working.ToArray()) + ") and " : "")
                + "the connection underneath still work. That points at the filter's HTTPS inspection, not the internet line.";
        }

        // Names the web checks that are failing, so "Degraded" says which site is in trouble.
        private string ExplainDegraded(Sample s)
        {
            List<string> failing = new List<string>();
            string detail = null;
            bool sameDetail = true;
            for (int i = 0; i < s.Schema.Defs.Length; i++)
            {
                CheckDef d = s.Schema.Defs[i];
                if (d.Kind != "HTTP" || d.Service || !s.R[i].Tested || s.R[i].Ok) continue;
                if (engine != null && engine.IsHttpExcluded(i)) continue;
                failing.Add(d.Name);
                if (detail == null) detail = s.R[i].Detail; else if (detail != s.R[i].Detail) sameDetail = false;
            }
            if (failing.Count == 0) return St.Explain(s.Status);

            string names = failing.Count == 1 ? failing[0]
                : string.Join(", ", failing.GetRange(0, failing.Count - 1).ToArray()) + " and " + failing[failing.Count - 1];
            string why = "";
            if (sameDetail && detail != null)
            {
                why = Friendly(detail);
                int paren = why.IndexOf(" (");
                if (paren > 0) why = why.Substring(0, paren);
                why = " (" + why.ToLowerInvariant() + ")";
            }
            bool one = failing.Count == 1;
            return names + (one ? " is" : " are") + " not answering" + why + " while the other web checks succeed. The connection is up, but anything that relies on "
                + (one ? "that site" : "those sites") + " may be slow or fail to load.";
        }

        private void FillList(Schema schema, Sample s) { FillList(schema, s, null, null); }

        private void FillList(Schema schema, Sample s, int[] tests, int[] oks)
        {
            list.BeginUpdate();
            if (list.Items.Count != schema.Defs.Length)
            {
                list.Items.Clear();
                foreach (CheckDef d in schema.Defs)
                {
                    ListViewItem it = new ListViewItem((d.Service ? "Service check" : d.KindLabel) + (d.Kind == "HTTP" || d.Kind == "TCP" ? ": " + d.Name : ""));
                    it.UseItemStyleForSubItems = false;
                    it.SubItems.Add(d.Region);
                    it.SubItems.Add(d.Target);
                    it.SubItems.Add("");
                    it.SubItems.Add("");
                    it.SubItems.Add("");
                    it.SubItems[1].ForeColor = Theme.Ink2;
                    it.SubItems[2].ForeColor = Theme.Ink2;
                    list.Items.Add(it);
                }
            }
            for (int i = 0; i < schema.Defs.Length; i++)
            {
                ListViewItem it = list.Items[i];
                string result = "", time = "";
                Color color = Theme.Muted;

                // Share of this session's tests that succeeded. Updated even on rounds when the check was not due.
                string rate = "";
                Color rateColor = Theme.Ink2;
                if (tests != null && i < tests.Length && tests[i] > 0)
                {
                    int fails = tests[i] - oks[i];
                    double pct = 100.0 * oks[i] / tests[i];
                    rate = fails == 0 ? "100%" : Math.Min(pct, 99.9).ToString("0.0") + "%";
                    bool ignored = engine != null && ((schema.Defs[i].Kind == "HTTP" && engine.IsHttpExcluded(i))
                        || (schema.Defs[i].Kind == "TCP" && engine.DirectBlockedByPolicy));
                    if (ignored) rateColor = Theme.Muted;
                    else if (pct < 99.0) rateColor = Theme.Critical;
                    it.ToolTipText = fails == 0 ? "" : fails.ToString("N0") + " of " + tests[i].ToString("N0") + " tests failed in this session";
                }
                else if (s == null) it.ToolTipText = "";
                if (it.SubItems[5].Text != rate) it.SubItems[5].Text = rate;
                if (it.SubItems[5].ForeColor != rateColor) it.SubItems[5].ForeColor = rateColor;

                if (s != null)
                {
                    CheckResult r = s.R[i];
                    if (!r.Tested && schema.Defs[i].Kind == "HTTP")
                    {
                        // Not due this round: keep showing the last real result.
                        if (engine != null && engine.IsHttpPaused(i)) { result = "Paused 15 min (site asked us to slow down)"; }
                        else if (it.SubItems[3].Text.Length > 0 && !it.SubItems[3].Text.StartsWith("Paused")) continue;
                        else result = "Checked once every " + settings.Http[i].EverySec + " s";
                    }
                    else if (!r.Tested) result = schema.Defs[i].Kind == "PROXY" ? "No proxy configured" : "Not available";
                    else if (r.Ok)
                    {
                        result = "OK"; time = r.Ms + " ms"; color = Theme.Good;
                        // The filter is decrypting this site: worth seeing at a glance, because those are the ones an inspection fault hits.
                        if (schema.Defs[i].Kind == "HTTP" && engine != null && engine.IsHttpInspected(i)) result = "OK · decrypted by filter";
                    }
                    else
                    {
                        result = Friendly(r.Detail); color = Theme.Critical;
                        bool http = schema.Defs[i].Kind == "HTTP", tcp = schema.Defs[i].Kind == "TCP";
                        if (http && engine != null && engine.IsHttpExcluded(i)) { result = "Blocked by filter (ignored)"; color = Theme.Muted; }
                        if (tcp && engine != null && engine.DirectBlockedByPolicy) { result = "Not permitted here (ignored)"; color = Theme.Muted; }
                    }
                }
                if (it.SubItems[3].Text != result) it.SubItems[3].Text = result;
                if (it.SubItems[3].ForeColor != color) it.SubItems[3].ForeColor = color;
                if (it.SubItems[4].Text != time) it.SubItems[4].Text = time;
            }
            list.EndUpdate();
        }

        internal static string Friendly(string detail)
        {
            switch (detail)
            {
                case "TIMEOUT": return "Timed out";
                case "DNS_TIMEOUT": return "Name lookup timed out";
                case "CONNECT_TIMEOUT": return "Could not connect (timed out)";
                case "TLS_TIMEOUT": return "Secure handshake timed out";
                case "TLS_RESET": return "Secure handshake dropped";
                case "RESPONSE_TIMEOUT": return "Connected, but no reply";
                case "DNS_FAIL": return "Name lookup failed";
                case "PROXY_DNS_FAIL": return "Proxy name lookup failed";
                case "CONNECT_FAIL": return "Could not connect";
                case "UNREACHABLE": return "Network unreachable";
                case "REFUSED": return "Connection refused";
                case "TLS_ERROR": return "Certificate / TLS error";
                case "CONNECTION_RESET": return "Connection dropped";
                case "UNEXPECTED_CONTENT": return "Intercepted (block page?)";
                case "REDIRECTED": return "Redirected (sign-in page?)";
                case "PROXY_AUTH": return "Proxy sign-in required";
                case "BLOCKED": return "Blocked (403)";
                case "GATEWAY_ERROR": return "Proxy / gateway error";
                case "NO_REPLY": return "No reply";
                case "SERVFAIL": return "DNS server failure";
                default: return detail;
            }
        }

        // ------------------------------------------------------------------ stop / report
        private void OnStopped(bool timedOut)
        {
            clock.Stop();
            cboAdapter.Enabled = cboInterval.Enabled = cboDuration.Enabled = chkAwake.Enabled = true;
            btnStart.Enabled = true;
            btnStart.Text = "Start monitoring";
            StyleButton(btnStart, true);
            Text = AppInfo.Name;
            lblElapsed.Text = "Stopped";

            bool hasData = engine != null && engine.Stats.Samples > 0;
            if (closeWhenStopped)
            {
                if (hasData) MakeReportNow("session");
                Close();
                return;
            }
            dot.DotColor = Theme.Idle;
            lblStatus.Text = timedOut ? "Monitoring finished" : "Monitoring stopped";
            lblExplain.Text = hasData ? "Preparing the report…" : "No checks were completed.";
            if (!hasData) return;

            bool ask = !timedOut;
            Task.Factory.StartNew<string>(delegate { return MakeReportNow("session"); }).ContinueWith(delegate(Task<string> t)
            {
                Post(delegate
                {
                    string path = t.Status == TaskStatus.RanToCompletion ? t.Result : null;
                    if (path == null) { lblExplain.Text = "The report could not be saved. Use View report to try again."; return; }
                    lblExplain.Text = "Report saved: " + Path.GetFileName(path) + ". Use View report to open it.";
                    if (ask && MessageBox.Show(this, "Monitoring has stopped and a report has been saved.\n\nOpen the report now?", AppInfo.Name,
                            MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                        OpenPath(path);
                });
            });
        }

        private void MakeReport(string scope, bool open)
        {
            if (scope == "session" && (engine == null || engine.Stats.Samples == 0))
            {
                MessageBox.Show(this, "Nothing has been recorded in this session yet.\n\nPress Start monitoring first, or choose one of the saved-log reports.",
                    AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (scope == "session" && lastReportPath != null && !engine.IsRunning && File.Exists(lastReportPath))
            {
                OpenPath(lastReportPath);
                return;
            }
            btnReport.Enabled = false;
            Cursor = Cursors.WaitCursor;
            Task.Factory.StartNew<string>(delegate { return MakeReportNow(scope); }).ContinueWith(delegate(Task<string> t)
            {
                Post(delegate
                {
                    btnReport.Enabled = true;
                    Cursor = Cursors.Default;
                    string path = t.Status == TaskStatus.RanToCompletion ? t.Result : null;
                    if (path == null)
                    {
                        string why = t.Exception != null ? t.Exception.GetBaseException().Message : "No saved data was found for that period.";
                        MessageBox.Show(this, "The report could not be created.\n\n" + why, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                    else if (open) OpenPath(path);
                });
            });
        }

        // Combined report across every computer whose logs are in one folder.
        private void MakeCombined(string folder, bool subfolders, int days)
        {
            btnReport.Enabled = false;
            Cursor = Cursors.WaitCursor;
            DateTime now = DateTime.Now;
            string label = "All computers, last " + days + " days";
            Task.Factory.StartNew<string>(delegate
            {
                return FleetReport.Save(folder, subfolders, now.Date.AddDays(-(days - 1)), now, settings.Organisation, label, store.ReportDir);
            }).ContinueWith(delegate(Task<string> t)
            {
                Post(delegate
                {
                    btnReport.Enabled = true;
                    Cursor = Cursors.Default;
                    string path = t.Status == TaskStatus.RanToCompletion ? t.Result : null;
                    if (path == null)
                    {
                        string why = t.Exception != null ? t.Exception.GetBaseException().Message
                            : "No log files from the last " + days + " days were found in:\n" + folder;
                        MessageBox.Show(this, "The combined report could not be created.\n\n" + why, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                    else OpenPath(path);
                });
            });
        }

        /// <summary>Builds and saves a report. Safe to call from a background thread. Returns null when there is no data.</summary>
        private string MakeReportNow(string scope)
        {
            Engine eng = engine;
            ReportContext ctx = new ReportContext();
            ctx.Organisation = settings.Organisation;
            List<Sample> samples;

            if (scope == "session")
            {
                if (eng == null) return null;
                samples = eng.Snapshot();
                ctx.PeriodLabel = "This monitoring session";
                if (store.CurrentFile != null) ctx.LogFiles.Add(Path.GetFileName(store.CurrentFile));
            }
            else
            {
                DateTime now = DateTime.Now;
                DateTime from = scope == "today" ? now.Date : now.Date.AddDays(-(int.Parse(scope) - 1));
                ctx.PeriodLabel = scope == "today" ? "Today, from saved logs" : "Last " + scope + " days, from saved logs";
                samples = store.Read(from, now, ctx.LogFiles);
            }
            if (samples.Count == 0) return null;

            Schema schema = eng != null ? eng.Schema : BuildPreviewSchema();
            foreach (CheckDef d in schema.Defs)
            {
                ctx.Targets[d.Key] = d.Target; ctx.Regions[d.Key] = d.Region;
                if (d.Service) ctx.Service.Add(d.Key);
            }
            ctx.Traces = scope == "session" ? eng.TraceSnapshot() : store.ReadTraces(samples[0].Time.AddSeconds(-5), DateTime.Now);
            ctx.Certs = scope == "session" ? eng.CertSnapshot() : store.ReadCerts(samples[0].Time.AddSeconds(-5), DateTime.Now);
            ctx.TimeoutMs = settings.TimeoutMs;
            ctx.WifiWhyNot = Wifi.Allowed ? (Wifi.AccessDenied ? "Windows refused access" : "") : Wifi.WhyNot;

            NetInfo net = eng != null ? eng.Net : NetInfo.Detect();
            ProxyInfo proxy = eng != null ? eng.Proxy : ProxyInfo.Detect(settings.Http[0].Url);
            List<KeyValuePair<string, string>> env = ctx.Environment;
            env.Add(Pair("Computer", Environment.MachineName));
            env.Add(Pair("Signed-in user", Environment.UserDomainName + "\\" + Environment.UserName));
            env.Add(Pair("Windows", Environment.OSVersion.Version.ToString()));
            bool chosen = eng != null && eng.AdapterId.Length > 0;
            if (net.AdapterName.Length > 0)
                env.Add(Pair("Network adapter", net.AdapterName + " (" + net.AdapterType + (chosen ? "; chosen in the window" : "; chosen by Windows") + ")"));
            if (!chosen && eng != null)
            {
                // Two ways out and nobody said which to use: say so, because the results are a blend of both.
                List<string> routes = new List<string>();
                foreach (NetInfo n in NetInfo.All()) { if (n.Gateway != null) routes.Add(n.AdapterName + " (gateway " + n.Gateway + ")"); }
                if (routes.Count > 1)
                    ctx.Notes.Add("This computer has " + routes.Count + " network connections with a route to the internet: " + string.Join(", ", routes.ToArray())
                        + ". The monitor was left on Automatic, so Windows decided which one each check went out through, and that can change from moment to moment. "
                        + "To test one connection on its own, choose it under Network adapter before starting.");
            }
            if (net.Gateway != null) env.Add(Pair("Default gateway", net.Gateway.ToString()));
            if (net.DnsServers.Count > 0)
            {
                List<string> dns = new List<string>();
                foreach (System.Net.IPAddress a in net.DnsServers) dns.Add(a.ToString());
                env.Add(Pair("DNS servers", string.Join(", ", dns.ToArray())));
            }
            env.Add(Pair("Proxy", proxy.Description));
            if (eng != null)
            {
                HashSet<string> issuers = new HashSet<string>();
                foreach (CertRecord cr in eng.CertSnapshot()) issuers.Add(ShortIssuer(cr.Issuer));
                List<string> sites;
                lock (eng.ServedFrom) { sites = new List<string>(eng.ServedFrom); }
                if (sites.Count > 0)
                    env.Add(Pair("Cloudflare answered from", string.Join(", ", sites.ToArray()) + " (airport code of its site; LHR and MAN are in the UK)"));
                if (issuers.Count > 0) env.Add(Pair("HTTPS certificates issued by", string.Join("; ", new List<string>(issuers).ToArray())));
                if (scope == "session")
                    env.Add(Pair("Check frequency", eng.IntervalMs == 0 ? "Adaptive (5 s, 1 s during problems)" : "Every " + (eng.IntervalMs / 1000) + " s"));
            }
            env.Add(Pair("Timeout per check", (settings.TimeoutMs / 1000.0).ToString("0.#") + " s"));
            env.Add(Pair("Data folder", store.Root));
            if (store.LastError != null) ctx.Notes.Add("The log file could not be written at times (" + store.LastError + "), so saved logs may be incomplete.");

            string path = ReportBuilder.Save(store.ReportDir, samples, ctx);
            if (scope == "session") lastReportPath = path;
            return path;
        }

        private static KeyValuePair<string, string> Pair(string k, string v)
        {
            return new KeyValuePair<string, string>(k, v);
        }

        private static string ShortIssuer(string issuer)
        {
            Match o = Regex.Match(issuer, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
            Match cn = Regex.Match(issuer, @"(?:^|,\s*)CN=(""[^""]+""|[^,]+)");
            string name = cn.Success ? cn.Groups[1].Value.Trim('"') : issuer;
            if (o.Success) name += " (" + o.Groups[1].Value.Trim('"') + ")";
            return name;
        }

        private void OpenPath(string path)
        {
            try { Process.Start(path); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Could not open:\n" + path + "\n\n" + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (engine != null && engine.IsRunning && !closeWhenStopped)
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    DialogResult r = MessageBox.Show(this, "Monitoring is still running.\n\nStop monitoring, save the report and close?", AppInfo.Name,
                        MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
                    if (r != DialogResult.OK) { e.Cancel = true; return; }
                    e.Cancel = true;
                    closeWhenStopped = true;
                    StopMonitoring();
                    return;
                }
                // Sign-out or shutdown: the CSV is already on disk, just stop cleanly.
                engine.Stop();
            }
            base.OnFormClosing(e);
        }
    }
}
