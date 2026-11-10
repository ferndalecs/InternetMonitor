// Internet Monitor - combined report across many computers.
//
// Reads every computer's log files from one folder (typically a network share that
// all copies of the program save to) and works out which outages hit everybody at
// once and which were limited to one or two computers.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace InternetMonitor
{
    internal static class FleetReport
    {
        private const int MaxRows = 40;
        private const int MaxIncidents = 300;

        private sealed class Interval
        {
            public DateTime Start, End;
            public double Sec;
            public Dictionary<string, double> Codes = new Dictionary<string, double>();
        }

        private sealed class Pc
        {
            public string Name, Site;
            public double Mon, Down, Deg, SiteDown, LocalDown;
            public List<Interval> Outs = new List<Interval>();
            public List<Interval> Cover = new List<Interval>();
            public double[] On, DegB, DownB;
            public List<int> Ms = new List<int>();
            public HashSet<string> Ips = new HashSet<string>();
            public string Label { get { return Site.Length > 0 ? Site + " / " + Name : Name; } }
        }

        private sealed class Cluster
        {
            public DateTime Start, End;
            public string Site;
            public List<Pc> Affected = new List<Pc>();
            public int Monitoring;
            public int Scope;       // 2 = site-wide, 1 = local, 0 = cannot tell (only one computer monitoring)
            public Dictionary<string, double> Codes = new Dictionary<string, double>();
        }

        private sealed class Ap
        {
            public string Bssid, Ssid;
            public double Sec, Down;
            public HashSet<string> Pcs = new HashSet<string>();
        }

        private static readonly Regex LogName = new Regex(@"^InternetLog_(.+)_(\d{4}-\d{2}-\d{2})(?:_\d+)?\.csv$", RegexOptions.IgnoreCase);

        /// <summary>Builds and saves the combined report. Returns null when the folder holds no data for the period.</summary>
        public static string Save(string folder, bool includeSubfolders, DateTime from, DateTime to, string organisation, string periodLabel, string reportDir)
        {
            // ---- find the files, grouped by site (sub-folder) and computer ------------
            SortedDictionary<string, List<string>> groups = new SortedDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            string[] files;
            try { files = Directory.GetFiles(folder, "InternetLog_*.csv", includeSubfolders ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly); }
            catch { return null; }
            foreach (string file in files)
            {
                Match m = LogName.Match(Path.GetFileName(file));
                if (!m.Success) continue;
                DateTime day;
                if (!DateTime.TryParseExact(m.Groups[2].Value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out day)) continue;
                if (day < from.Date || day > to.Date) continue;
                string key = SiteOf(folder, file) + "|" + m.Groups[1].Value;
                if (!groups.ContainsKey(key)) groups[key] = new List<string>();
                groups[key].Add(file);
            }
            if (groups.Count == 0) return null;

            // ---- a time grid fitted to where the data actually is -------------------------
            // (peeking at the first and last line of each file is far cheaper than reading them all twice)
            DateTime dataFrom = DateTime.MaxValue, dataTo = DateTime.MinValue;
            foreach (List<string> list in groups.Values)
            {
                foreach (string file in list)
                {
                    DateTime a, b;
                    if (!Extent(file, out a, out b)) continue;
                    if (a < dataFrom) dataFrom = a;
                    if (b > dataTo) dataTo = b;
                }
            }
            if (dataFrom > dataTo) return null;
            if (dataFrom > from) from = dataFrom;
            if (dataTo.AddSeconds(30) < to) to = dataTo.AddSeconds(30);
            if (to <= from) return null;

            double span = Math.Max(1, (to - from).TotalSeconds);
            int step = 86400;
            foreach (int c in ReportBuilder.NiceSteps) { if (c >= 10 && span / c <= 240) { step = c; break; } }
            DateTime gridStart = from.Date.AddSeconds(Math.Floor((from - from.Date).TotalSeconds / step) * step);
            int nb = Math.Max(1, (int)Math.Ceiling((to - gridStart).TotalSeconds / step));

            // ---- one computer at a time, so memory stays small however many there are ----
            List<Pc> pcs = new List<Pc>();
            Dictionary<string, Ap> aps = new Dictionary<string, Ap>();
            foreach (KeyValuePair<string, List<string>> g in groups)
            {
                List<Sample> samples = new List<Sample>();
                foreach (string file in g.Value)
                {
                    try { LogStore.ReadFile(file, from, to, samples); } catch { }
                }
                if (samples.Count == 0) continue;
                samples.Sort(delegate(Sample a, Sample b) { return a.Time.CompareTo(b.Time); });
                int bar = g.Key.IndexOf('|');
                Pc pc = new Pc();
                pc.Site = g.Key.Substring(0, bar);
                pc.Name = g.Key.Substring(bar + 1);
                pc.On = new double[nb]; pc.DegB = new double[nb]; pc.DownB = new double[nb];
                Digest(pc, samples, gridStart, step, nb, aps);
                pcs.Add(pc);
            }
            if (pcs.Count == 0) return null;

            // ---- group overlapping outages, site by site ---------------------------------
            List<Cluster> clusters = new List<Cluster>();
            Dictionary<string, List<Pc>> bySite = new Dictionary<string, List<Pc>>(StringComparer.OrdinalIgnoreCase);
            foreach (Pc pc in pcs)
            {
                if (!bySite.ContainsKey(pc.Site)) bySite[pc.Site] = new List<Pc>();
                bySite[pc.Site].Add(pc);
            }
            foreach (KeyValuePair<string, List<Pc>> site in bySite)
            {
                List<KeyValuePair<Interval, Pc>> all = new List<KeyValuePair<Interval, Pc>>();
                foreach (Pc pc in site.Value) foreach (Interval iv in pc.Outs) all.Add(new KeyValuePair<Interval, Pc>(iv, pc));
                all.Sort(delegate(KeyValuePair<Interval, Pc> a, KeyValuePair<Interval, Pc> b) { return a.Key.Start.CompareTo(b.Key.Start); });

                Cluster cur = null;
                List<KeyValuePair<Interval, Pc>> members = new List<KeyValuePair<Interval, Pc>>();
                Action close = delegate
                {
                    if (cur == null) return;
                    foreach (Pc pc in site.Value)
                    {
                        foreach (Interval cv in pc.Cover)
                        {
                            if (cv.Start <= cur.End.AddSeconds(30) && cv.End >= cur.Start.AddSeconds(-30)) { cur.Monitoring++; break; }
                        }
                    }
                    cur.Monitoring = Math.Max(cur.Monitoring, cur.Affected.Count);
                    // Site-wide = at least two computers, and at least half of those watching, went down together.
                    cur.Scope = cur.Monitoring <= 1 ? 0 : (cur.Affected.Count >= 2 && cur.Affected.Count * 2 >= cur.Monitoring) ? 2 : 1;
                    foreach (KeyValuePair<Interval, Pc> mbr in members)
                    {
                        if (cur.Scope == 2) mbr.Value.SiteDown += mbr.Key.Sec; else mbr.Value.LocalDown += mbr.Key.Sec;
                    }
                    clusters.Add(cur);
                    cur = null; members.Clear();
                };
                foreach (KeyValuePair<Interval, Pc> item in all)
                {
                    if (cur != null && item.Key.Start > cur.End.AddSeconds(10)) close();
                    if (cur == null) { cur = new Cluster(); cur.Site = site.Key; cur.Start = item.Key.Start; cur.End = item.Key.End; }
                    if (item.Key.End > cur.End) cur.End = item.Key.End;
                    if (!cur.Affected.Contains(item.Value)) cur.Affected.Add(item.Value);
                    foreach (KeyValuePair<string, double> kv in item.Key.Codes)
                    {
                        double v; cur.Codes.TryGetValue(kv.Key, out v); cur.Codes[kv.Key] = v + kv.Value;
                    }
                    members.Add(item);
                }
                close();
            }
            clusters.Sort(delegate(Cluster a, Cluster b) { return b.Start.CompareTo(a.Start); });

            // ---- trim the grid to where there is data ------------------------------------
            int first = nb, last = -1;
            foreach (Pc pc in pcs)
            {
                for (int b = 0; b < nb; b++)
                {
                    if (pc.On[b] + pc.DegB[b] + pc.DownB[b] <= 0) continue;
                    if (b < first) first = b;
                    if (b > last) last = b;
                }
            }
            if (last < first) return null;
            int n = last - first + 1;
            DateTime t0 = gridStart.AddSeconds((double)first * step), tEnd = gridStart.AddSeconds((double)(last + 1) * step);
            bool multiDay = t0.Date != tEnd.AddSeconds(-1).Date;
            string tf = multiDay ? "d MMM HH:mm:ss" : "HH:mm:ss";

            // ---- totals ------------------------------------------------------------------
            int siteWide = 0, local = 0, single = 0;
            double siteWideSec = 0;
            foreach (Cluster c in clusters)
            {
                if (c.Scope == 2) { siteWide++; siteWideSec += (c.End - c.Start).TotalSeconds; }
                else if (c.Scope == 1) local++;
                else single++;
            }
            pcs.Sort(delegate(Pc a, Pc b) { int c = b.Down.CompareTo(a.Down); return c != 0 ? c : string.Compare(a.Label, b.Label, StringComparison.OrdinalIgnoreCase); });
            Pc worstLocal = null;
            foreach (Pc pc in pcs) { if (pc.LocalDown > 0 && (worstLocal == null || pc.LocalDown > worstLocal.LocalDown)) worstLocal = pc; }

            // ---- output ------------------------------------------------------------------
            Dictionary<string, object> data = new Dictionary<string, object>();
            data["mode"] = "fleet";
            data["empty"] = false;
            Dictionary<string, object> meta = new Dictionary<string, object>();
            meta["org"] = organisation;
            meta["title"] = "Combined Connectivity Report";
            meta["computer"] = pcs.Count + (pcs.Count == 1 ? " computer" : " computers") + (bySite.Count > 1 ? " at " + bySite.Count + " sites" : "");
            meta["generated"] = DateTime.Now.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture);
            meta["period"] = periodLabel;
            meta["version"] = AppInfo.Version;
            meta["logFiles"] = new string[] { folder };
            data["meta"] = meta;

            Dictionary<string, object> statuses = new Dictionary<string, object>();
            foreach (string code in St.All)
            {
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["label"] = St.Label(code); o["sev"] = St.Severity(code); o["explain"] = St.Explain(code);
                statuses[code] = o;
            }
            data["statuses"] = statuses;

            Dictionary<string, object> summary = new Dictionary<string, object>();
            summary["start"] = t0.ToString("ddd d MMM yyyy HH:mm", CultureInfo.InvariantCulture);
            summary["end"] = tEnd.ToString("ddd d MMM yyyy HH:mm", CultureInfo.InvariantCulture);
            summary["computers"] = pcs.Count;
            summary["siteWide"] = siteWide;
            summary["siteWideDur"] = siteWide > 0 ? ReportBuilder.Duration(siteWideSec) : "none";
            summary["local"] = local;
            summary["single"] = single;
            summary["worst"] = worstLocal != null ? worstLocal.Label : "–";
            summary["worstDur"] = worstLocal != null ? ReportBuilder.Duration(worstLocal.LocalDown) + " of local downtime" : "no local downtime";
            data["summary"] = summary;

            List<string> verdict = new List<string>();
            string level, headline;
            if (clusters.Count == 0) { level = "good"; headline = "No outages on any computer"; }
            else
            {
                level = siteWide > 0 ? "critical" : "warning";
                List<string> parts = new List<string>();
                if (siteWide > 0) parts.Add(siteWide + (siteWide == 1 ? " site-wide outage" : " site-wide outages"));
                if (local > 0) parts.Add(local + (local == 1 ? " local incident" : " local incidents"));
                if (single > 0) parts.Add(single + " unclassified");
                headline = string.Join(", ", parts.ToArray());
            }
            verdict.Add(pcs.Count + (pcs.Count == 1 ? " computer was" : " computers were") + " monitored"
                + (bySite.Count > 1 ? " across " + bySite.Count + " sites (one per sub-folder; outages are compared within a site, never between sites)" : "") + ".");
            if (siteWide > 0)
                verdict.Add((siteWide == 1 ? "1 outage" : siteWide + " outages") + " hit at least half of the computers that were monitoring at the time, lasting "
                    + ReportBuilder.Duration(siteWideSec) + " in total. An outage shared like that points at something they all depend on: the internet line, the firewall or the web filter.");
            if (local > 0)
                verdict.Add((local == 1 ? "1 incident was" : local + " incidents were") + " limited to a minority of computers while the others stayed online. "
                    + "That points at Wi-Fi coverage, cabling, a switch, or the computers themselves, not the internet line."
                    + (worstLocal != null ? " The most affected was " + worstLocal.Label + " (" + ReportBuilder.Duration(worstLocal.LocalDown) + ")." : ""));
            if (single > 0)
                verdict.Add((single == 1 ? "1 outage" : single + " outages") + " happened while only one computer was monitoring, so there was nothing to compare against.");
            if (pcs.Count == 1)
                verdict.Add("Only one computer's logs were found. Run the monitor on several computers saving to the same folder to tell shared faults from local ones.");
            data["level"] = level; data["headline"] = headline; data["verdict"] = verdict;

            // swim lanes
            Dictionary<string, object> fleet = new Dictionary<string, object>();
            fleet["t0"] = ReportBuilder.Epoch(t0);
            fleet["step"] = step;
            fleet["n"] = n;
            bool[] wide = new bool[n];
            foreach (Cluster c in clusters)
            {
                if (c.Scope != 2) continue;
                int b0 = Math.Max(0, (int)Math.Floor((c.Start - t0).TotalSeconds / step));
                int b1 = Math.Min(n - 1, (int)Math.Floor((c.End - t0).TotalSeconds / step));
                for (int b = b0; b <= b1; b++) wide[b] = true;
            }
            fleet["wide"] = wide;
            List<object> rows = new List<object>();
            for (int i = 0; i < pcs.Count && i < MaxRows; i++)
            {
                Pc pc = pcs[i];
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["name"] = pc.Label;
                o["on"] = Slice(pc.On, first, n); o["deg"] = Slice(pc.DegB, first, n); o["down"] = Slice(pc.DownB, first, n);
                rows.Add(o);
            }
            fleet["rows"] = rows;
            fleet["hidden"] = Math.Max(0, pcs.Count - MaxRows);

            // incidents
            List<object> incRows = new List<object>();
            for (int i = 0; i < clusters.Count && i < MaxIncidents; i++)
            {
                Cluster c = clusters[i];
                string cause = St.InternetDown; double best = -1;
                foreach (KeyValuePair<string, double> kv in c.Codes) { if (kv.Value > best) { best = kv.Value; cause = kv.Key; } }
                List<string> who = new List<string>();
                foreach (Pc pc in c.Affected) { if (who.Count < 5) who.Add(pc.Name); }
                if (c.Affected.Count > 5) who.Add("+" + (c.Affected.Count - 5) + " more");
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["start"] = c.Start.ToString(tf, CultureInfo.InvariantCulture);
                o["end"] = c.End.ToString(tf, CultureInfo.InvariantCulture);
                o["dur"] = ReportBuilder.Duration((c.End - c.Start).TotalSeconds);
                o["scope"] = c.Scope;
                o["scopeText"] = (c.Scope == 2 ? "Site-wide" : c.Scope == 1 ? "Local" : "Unclassified")
                    + " (" + c.Affected.Count + " of " + c.Monitoring + (c.Monitoring == 1 ? " computer)" : " computers)");
                o["site"] = c.Site;
                o["cause"] = St.Label(cause);
                o["who"] = string.Join(", ", who.ToArray());
                incRows.Add(o);
            }
            fleet["incidents"] = incRows;
            fleet["incidentsTotal"] = clusters.Count;
            fleet["sites"] = bySite.Count;

            // per computer
            List<object> pcRows = new List<object>();
            foreach (Pc pc in pcs)
            {
                pc.Ms.Sort();
                List<string> ips = new List<string>(pc.Ips);
                if (ips.Count > 3) { int extra = ips.Count - 3; ips = ips.GetRange(0, 3); ips.Add("+" + extra); }
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["name"] = pc.Label;
                o["mon"] = ReportBuilder.Duration(pc.Mon);
                o["avail"] = Math.Round(pc.Mon > 0 ? 100.0 * (pc.Mon - pc.Down) / pc.Mon : 100.0, 2);
                o["outages"] = pc.Outs.Count;
                o["down"] = pc.Down > 0 ? ReportBuilder.Duration(pc.Down) : "none";
                o["shared"] = pc.SiteDown > 0 ? ReportBuilder.Duration(pc.SiteDown) : "–";
                o["local"] = pc.LocalDown > 0 ? ReportBuilder.Duration(pc.LocalDown) : "–";
                o["med"] = pc.Ms.Count > 0 ? (object)(int)Math.Round(ReportBuilder.Percentile(pc.Ms, 0.5)) : null;
                o["ips"] = string.Join(", ", ips.ToArray());
                pcRows.Add(o);
            }
            fleet["computers"] = pcRows;

            // access points
            List<Ap> apList = new List<Ap>(aps.Values);
            apList.Sort(delegate(Ap a, Ap b) { return b.Down.CompareTo(a.Down); });
            List<object> apRows = new List<object>();
            for (int i = 0; i < apList.Count && i < 40; i++)
            {
                Ap ap = apList[i];
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["bssid"] = ap.Bssid; o["ssid"] = ap.Ssid; o["pcs"] = ap.Pcs.Count;
                o["dur"] = ReportBuilder.Duration(ap.Sec); o["down"] = ap.Down > 0 ? ReportBuilder.Duration(ap.Down) : "none";
                apRows.Add(o);
            }
            fleet["aps"] = apRows;
            data["fleet"] = fleet;

            // ---- render ------------------------------------------------------------------
            JavaScriptSerializer json = new JavaScriptSerializer();
            json.MaxJsonLength = int.MaxValue;
            string template;
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("ReportTemplate.html"))
            using (StreamReader r = new StreamReader(s, Encoding.UTF8)) template = r.ReadToEnd();
            string html = template.Replace("{{TITLE}}", "Combined Connectivity Report").Replace("\"{{DATA}}\"", json.Serialize(data));

            Directory.CreateDirectory(reportDir);
            string path = Path.Combine(reportDir, "CombinedReport_" + DateTime.Now.ToString("yyyy-MM-dd_HHmmss") + ".html");
            File.WriteAllText(path, html, new UTF8Encoding(false));
            return path;
        }

        // The first sub-folder under the chosen folder names the site ("Logs" folders are looked through).
        private static string SiteOf(string root, string file)
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(file)) ?? "";
            string full = Path.GetFullPath(root).TrimEnd('\\', '/');
            if (dir.Length <= full.Length) return "";
            foreach (string part in dir.Substring(full.Length).Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (!part.Equals("Logs", StringComparison.OrdinalIgnoreCase)) return part;
            }
            return "";
        }

        // First and last timestamp in a log file, without reading the middle.
        private static bool Extent(string file, out DateTime first, out DateTime last)
        {
            first = last = DateTime.MinValue;
            const string fmt = "yyyy-MM-dd HH:mm:ss";
            try
            {
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    StreamReader head = new StreamReader(fs, Encoding.UTF8);
                    head.ReadLine();
                    string line = head.ReadLine();
                    if (line == null || line.Length < 19
                        || !DateTime.TryParseExact(line.Substring(0, 19), fmt, CultureInfo.InvariantCulture, DateTimeStyles.None, out first)) return false;
                    last = first;

                    long tail = Math.Min(fs.Length, 2048);
                    fs.Seek(-tail, SeekOrigin.End);
                    byte[] buf = new byte[tail];
                    int read = fs.Read(buf, 0, buf.Length);
                    string[] lines = Encoding.UTF8.GetString(buf, 0, read).Split('\n');
                    for (int i = lines.Length - 1; i >= 0; i--)
                    {
                        DateTime t;
                        if (lines[i].Length >= 19 && DateTime.TryParseExact(lines[i].Substring(0, 19), fmt, CultureInfo.InvariantCulture, DateTimeStyles.None, out t))
                        {
                            if (t > last) last = t;
                            break;
                        }
                    }
                    return true;
                }
            }
            catch { return false; }
        }

        private static int[] Slice(double[] a, int start, int count)
        {
            int[] r = new int[count];
            for (int i = 0; i < count; i++) r[i] = (int)Math.Round(a[start + i]);
            return r;
        }

        private static void Digest(Pc pc, List<Sample> samples, DateTime gridStart, int step, int nb, Dictionary<string, Ap> aps)
        {
            int n = samples.Count;
            Interval outage = null, cover = null;
            for (int i = 0; i < n; i++)
            {
                Sample s = samples[i];
                double cap = Weights.CapSeconds(s.IntervalMs);
                double actual = i < n - 1 ? (samples[i + 1].Time - s.Time).TotalSeconds : s.IntervalMs / 1000.0;
                if (actual < 0) actual = 0;
                double w = Math.Min(actual, cap);
                bool gapAfter = i == n - 1 || actual > w + 0.5;
                int sev = St.Severity(s.Status);

                pc.Mon += w;
                if (sev == 2) pc.Down += w; else if (sev == 1) pc.Deg += w;
                if (!string.IsNullOrEmpty(s.ExternalIP)) pc.Ips.Add(s.ExternalIP);

                double pos = (s.Time - gridStart).TotalSeconds, left = w;
                while (left > 1e-9)
                {
                    int b = (int)Math.Floor(pos / step);
                    if (b < 0 || b >= nb) break;
                    double take = Math.Min(left, (b + 1) * (double)step - pos);
                    if (take <= 0) take = left;
                    if (sev == 0) pc.On[b] += take; else if (sev == 1) pc.DegB[b] += take; else pc.DownB[b] += take;
                    pos += take; left -= take;
                }

                long sum = 0; int cnt = 0;
                for (int c = 0; c < s.R.Length; c++)
                {
                    if (s.Schema.Defs[c].Kind == "HTTP" && s.R[c].Tested && s.R[c].Ok) { sum += s.R[c].Ms; cnt++; }
                }
                if (cnt > 0) pc.Ms.Add((int)(sum / cnt));

                if (s.WifiBssid.Length > 0)
                {
                    Ap ap;
                    if (!aps.TryGetValue(s.WifiBssid, out ap)) { ap = new Ap(); ap.Bssid = s.WifiBssid; ap.Ssid = s.WifiSsid; aps[s.WifiBssid] = ap; }
                    ap.Sec += w; ap.Pcs.Add(pc.Label);
                    if (sev == 2) ap.Down += w;
                }

                DateTime end = s.Time.AddSeconds(w);
                if (cover == null) { cover = new Interval(); cover.Start = s.Time; pc.Cover.Add(cover); }
                cover.End = end;

                if (sev == 2)
                {
                    if (outage == null) { outage = new Interval(); outage.Start = s.Time; pc.Outs.Add(outage); }
                    outage.End = end; outage.Sec += w;
                    double v; outage.Codes.TryGetValue(s.Status, out v); outage.Codes[s.Status] = v + w;
                }
                else outage = null;

                if (gapAfter) { cover = null; outage = null; }
            }
        }
    }
}
