// Internet Monitor - turns samples into a single self-contained HTML report.
// All the arithmetic happens here; the HTML template only draws what it is given.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;

namespace InternetMonitor
{
    internal sealed class ReportContext
    {
        public string Organisation = "";
        public string PeriodLabel = "";
        public List<string> LogFiles = new List<string>();
        public List<KeyValuePair<string, string>> Environment = new List<KeyValuePair<string, string>>();
        public List<string> Notes = new List<string>();
        public Dictionary<string, string> Targets = new Dictionary<string, string>();   // check key -> what it tests
        public Dictionary<string, string> Regions = new Dictionary<string, string>();   // check key -> where it is based
        public HashSet<string> Service = new HashSet<string>();                         // check keys reported separately
        public List<Trace> Traces = new List<Trace>();
        public List<CertRecord> Certs = new List<CertRecord>();                         // who issued each site's certificate
        public int TimeoutMs = 3000;
        public string WifiWhyNot = "";
    }

    internal static class ReportBuilder
    {
        private const int MaxBuckets = 240;
        private const int MaxIncidentRows = 300;

        internal static readonly int[] NiceSteps =
        {
            1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400
        };

        private sealed class CheckAgg
        {
            public string Kind, Name, Key;
            public bool Service;
            public int Tests, Ok;
            public List<int> Ms = new List<int>();
            public Dictionary<string, int> Fails = new Dictionary<string, int>();

            // Web checks only: failures while at least one other website still answered,
            // i.e. trouble with this one site rather than with the connection.
            public int SoloFails, Episodes;
            public double SoloSec, CurSec, LongestSec;
            public bool InEpisode;
            public DateTime CurStart, LongestAt;
            public List<DateTime> EpisodeStarts = new List<DateTime>();
            public Dictionary<string, int> SoloDetails = new Dictionary<string, int>();

            // Web checks only: time spent in each stage, where failures happened, and whether the filter decrypts the site.
            public List<int> Dns = new List<int>(), Tcp = new List<int>(), Tls = new List<int>();
            public int FailLookup, FailConnect, FailHandshake, FailReply, FailOther, Slow;
            public int InspectedTests, InspectedFails;
            public bool Inspected { get { return InspectedTests * 2 > Tests; } }
        }

        private sealed class IpAgg
        {
            public string Ip;
            public DateTime First, Last;
            public double Sec, DownSec, DegSec;
        }

        private sealed class Incident
        {
            public DateTime Start, End;
            public double Sec;
            public bool Ongoing;
            public Dictionary<string, int> StatusCounts = new Dictionary<string, int>();
            public Dictionary<string, int> FailCounts = new Dictionary<string, int>();
            public string Code;
            public int Sev;
            public int StartIndex;
        }

        private sealed class ApAgg
        {
            public string Bssid, Ssid;
            public double Sec, DownSec;
            public int OutagesBegan;
            public List<int> Signal = new List<int>();
        }

        public static string Save(string reportDir, List<Sample> samples, ReportContext ctx)
        {
            string html = Build(samples, ctx);
            string name = "InternetReport_" + LogStore.MachineTag + "_" + DateTime.Now.ToString("yyyy-MM-dd_HHmmss") + ".html";
            string path = Path.Combine(reportDir, name);
            Directory.CreateDirectory(reportDir);
            File.WriteAllText(path, html, new UTF8Encoding(false));
            return path;
        }

        public static string Build(List<Sample> samples, ReportContext ctx)
        {
            Dictionary<string, object> data = Compute(samples, ctx);
            JavaScriptSerializer json = new JavaScriptSerializer();
            json.MaxJsonLength = int.MaxValue;
            // JavaScriptSerializer escapes < > & as \u00xx, so the JSON is safe inside a <script> block.
            string payload = json.Serialize(data);

            string template;
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("ReportTemplate.html"))
            using (StreamReader r = new StreamReader(s, Encoding.UTF8)) template = r.ReadToEnd();

            string title = "Internet Connectivity Report" + (ctx.Organisation.Length > 0 ? " - " + ctx.Organisation : "");
            return template.Replace("{{TITLE}}", WebEscape(title)).Replace("\"{{DATA}}\"", payload);
        }

        private static string WebEscape(string s)
        {
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        internal static long Epoch(DateTime local)
        {
            // Local wall-clock time expressed as if it were UTC; the page reads it back with getUTC*().
            return (long)(local - new DateTime(1970, 1, 1)).TotalMilliseconds;
        }

        private static string KindShort(string kind)
        {
            switch (kind)
            {
                case "HTTP": return "Web";
                case "TCP": return "Direct";
                case "GW": return "Gateway";
                case "DNS": return "DNS";
                case "PROXY": return "Proxy";
                default: return kind;
            }
        }

        public static string Duration(double sec)
        {
            if (sec < 0) sec = 0;
            long s = (long)Math.Round(sec);
            if (s < 60) return s + "s";
            if (s < 3600) return (s / 60) + "m " + (s % 60).ToString("00") + "s";
            if (s < 86400) return (s / 3600) + "h " + ((s % 3600) / 60).ToString("00") + "m";
            return (s / 86400) + "d " + ((s % 86400) / 3600) + "h";
        }

        internal static double Percentile(List<int> sorted, double p)
        {
            if (sorted.Count == 0) return -1;
            double rank = p * (sorted.Count - 1);
            int lo = (int)Math.Floor(rank), hi = (int)Math.Ceiling(rank);
            return sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo);
        }

        private static Dictionary<string, object> Compute(List<Sample> samples, ReportContext ctx)
        {
            int n = samples.Count;
            Dictionary<string, object> data = new Dictionary<string, object>();

            Dictionary<string, object> meta = new Dictionary<string, object>();
            meta["org"] = ctx.Organisation;
            meta["computer"] = Environment.MachineName;
            meta["generated"] = DateTime.Now.ToString("d MMM yyyy HH:mm", CultureInfo.InvariantCulture);
            meta["period"] = ctx.PeriodLabel;
            meta["version"] = AppInfo.Version;
            meta["logFiles"] = ctx.LogFiles;
            data["meta"] = meta;

            Dictionary<string, object> statuses = new Dictionary<string, object>();
            foreach (string code in St.All)
            {
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["label"] = St.Label(code);
                o["sev"] = St.Severity(code);
                o["explain"] = St.Explain(code);
                statuses[code] = o;
            }
            data["statuses"] = statuses;
            data["empty"] = n == 0;
            if (n == 0)
            {
                data["env"] = PairList(ctx.Environment);
                return data;
            }

            DateTime start = samples[0].Time;

            // ---- how long each sample stands for -----------------------------------
            double[] w = new double[n];
            for (int i = 0; i < n; i++)
            {
                double cap = Weights.CapSeconds(samples[i].IntervalMs);
                double d = i < n - 1 ? (samples[i + 1].Time - samples[i].Time).TotalSeconds : samples[i].IntervalMs / 1000.0;
                if (d < 0) d = 0;
                w[i] = Math.Min(d, cap);
            }
            DateTime end = samples[n - 1].Time.AddSeconds(w[n - 1]);
            double span = Math.Max(1, (end - start).TotalSeconds);

            // ---- buckets for the timeline -------------------------------------------
            // Slots are never finer than twice the slowest check interval, so every slot holds data.
            int slowest = 1000;
            foreach (Sample s in samples) { if (s.IntervalMs > slowest) slowest = s.IntervalMs; }
            double minStep = Math.Min(120, 2 * slowest / 1000.0);
            int step = NiceSteps[NiceSteps.Length - 1];
            foreach (int c in NiceSteps) { if (c >= minStep && span / c <= MaxBuckets) { step = c; break; } }
            while (span / step > MaxBuckets) step += 86400;
            DateTime midnight = start.Date;
            DateTime t0 = midnight.AddSeconds(Math.Floor((start - midnight).TotalSeconds / step) * step);
            int nb = Math.Max(1, (int)Math.Ceiling((end - t0).TotalSeconds / step));

            double[] bOn = new double[nb], bDeg = new double[nb], bDown = new double[nb];
            Dictionary<string, double>[] bCause = new Dictionary<string, double>[nb];

            // ---- per-check aggregates (keyed by Kind_Name so mixed log files merge) --
            List<CheckAgg> checks = new List<CheckAgg>();
            Dictionary<string, CheckAgg> checkByKey = new Dictionary<string, CheckAgg>();
            Dictionary<Schema, CheckAgg[]> schemaMap = new Dictionary<Schema, CheckAgg[]>();
            Dictionary<string, List<int>[]> latency = new Dictionary<string, List<int>[]>();   // HTTP key -> per bucket

            Dictionary<string, double> statusSec = new Dictionary<string, double>();
            Dictionary<string, int> causeCount = new Dictionary<string, int>();
            foreach (string code in St.All) { statusSec[code] = 0; causeCount[code] = 0; }

            // ---- heat map: downtime by day and hour ---------------------------------
            List<DateTime> days = new List<DateTime>();
            Dictionary<DateTime, double[]> heatMon = new Dictionary<DateTime, double[]>();
            Dictionary<DateTime, double[]> heatDown = new Dictionary<DateTime, double[]>();

            List<Incident> incidents = new List<Incident>();
            Incident open = null;
            double monitored = 0, gapSec = 0;
            List<int> allHttpMs = new List<int>();

            // ---- HTTPS inspection: what else was working in the rounds when a decrypted site failed ----
            int inspRounds = 0, inspFailRounds = 0, inspAllFailRounds = 0, inspRoundsWithControl = 0, inspRoundsControlOk = 0;
            int inspRoundsDirectTested = 0, inspRoundsDirectOk = 0, inspRoundsDnsTested = 0, inspRoundsDnsOk = 0, inspRoundsGwTested = 0, inspRoundsGwOk = 0;
            int inspFailTotal = 0, inspFailHandshake = 0;
            List<int> inspFailTcpMs = new List<int>();

            // ---- Wi-Fi: signal over time, time on each access point, moves between them ----
            int[] bWifi = new int[nb];
            for (int b = 0; b < nb; b++) bWifi[b] = -1;
            Dictionary<string, ApAgg> aps = new Dictionary<string, ApAgg>();
            List<int> roamIndex = new List<int>();
            bool anyWifi = false, anyLink = false;
            List<int>[] bLink = new List<int>[nb];
            int maxLink = 0;
            HashSet<string> localIps = new HashSet<string>(), adapters = new HashSet<string>();

            // ---- public IP address: which one was in use, for how long, and when it changed ----
            List<IpAgg> ipList = new List<IpAgg>();
            Dictionary<string, IpAgg> ipByAddress = new Dictionary<string, IpAgg>();
            List<object> ipChanges = new List<object>();
            int ipChangeCount = 0;
            string lastIp = "";

            for (int i = 0; i < n; i++)
            {
                Sample s = samples[i];
                int sev = St.Severity(s.Status);
                if (!statusSec.ContainsKey(s.Status)) { statusSec[s.Status] = 0; causeCount[s.Status] = 0; }
                statusSec[s.Status] += w[i];
                monitored += w[i];
                if (!string.IsNullOrEmpty(s.LocalIP)) localIps.Add(s.LocalIP);
                if (!string.IsNullOrEmpty(s.Adapter)) adapters.Add(s.Adapter);
                if (!string.IsNullOrEmpty(s.ExternalIP))
                {
                    IpAgg ia;
                    if (!ipByAddress.TryGetValue(s.ExternalIP, out ia))
                    {
                        ia = new IpAgg(); ia.Ip = s.ExternalIP; ia.First = s.Time;
                        ipByAddress[s.ExternalIP] = ia; ipList.Add(ia);
                    }
                    ia.Last = s.Time;
                    ia.Sec += w[i];
                    if (sev == 2) ia.DownSec += w[i]; else if (sev == 1) ia.DegSec += w[i];
                    if (lastIp.Length > 0 && lastIp != s.ExternalIP)
                    {
                        ipChangeCount++;
                        ipChanges.Add(new string[] { s.Time.ToString("d MMM HH:mm:ss", CultureInfo.InvariantCulture), lastIp, s.ExternalIP });
                    }
                    lastIp = s.ExternalIP;
                }

                if (s.WifiLinkMbps >= 0)
                {
                    anyLink = true;
                    int lb2 = Math.Min(nb - 1, Math.Max(0, (int)Math.Floor((s.Time - t0).TotalSeconds / step)));
                    if (bLink[lb2] == null) bLink[lb2] = new List<int>();
                    bLink[lb2].Add(s.WifiLinkMbps);
                    if (s.WifiLinkMbps > maxLink) maxLink = s.WifiLinkMbps;
                }
                if (s.WifiBssid.Length > 0)
                {
                    anyWifi = true;
                    ApAgg ap;
                    if (!aps.TryGetValue(s.WifiBssid, out ap)) { ap = new ApAgg(); ap.Bssid = s.WifiBssid; ap.Ssid = s.WifiSsid; aps[s.WifiBssid] = ap; }
                    ap.Sec += w[i];
                    if (sev == 2) ap.DownSec += w[i];
                    if (s.WifiSignal >= 0)
                    {
                        ap.Signal.Add(s.WifiSignal);
                        int wb = Math.Min(nb - 1, Math.Max(0, (int)Math.Floor((s.Time - t0).TotalSeconds / step)));
                        if (bWifi[wb] < 0 || s.WifiSignal < bWifi[wb]) bWifi[wb] = s.WifiSignal;
                    }
                    if (i > 0 && samples[i - 1].WifiBssid.Length > 0 && samples[i - 1].WifiBssid != s.WifiBssid
                        && (s.Time - samples[i - 1].Time).TotalSeconds <= w[i - 1] + 0.5) roamIndex.Add(i);
                }

                bool gapAfter = false;
                if (i < n - 1)
                {
                    double actual = (samples[i + 1].Time - s.Time).TotalSeconds;
                    if (actual > w[i] + 0.5) { gapSec += actual - w[i]; gapAfter = true; }
                }

                // spread this sample's time across the buckets it covers
                double segStart = (s.Time - t0).TotalSeconds, left = w[i];
                while (left > 1e-9)
                {
                    int b = (int)Math.Floor(segStart / step);
                    if (b < 0 || b >= nb) break;
                    double take = Math.Min(left, (b + 1) * (double)step - segStart);
                    if (take <= 0) take = left;
                    if (sev == 0) bOn[b] += take; else if (sev == 1) bDeg[b] += take; else bDown[b] += take;
                    if (sev > 0)
                    {
                        if (bCause[b] == null) bCause[b] = new Dictionary<string, double>();
                        double cur; bCause[b].TryGetValue(s.Status, out cur); bCause[b][s.Status] = cur + take;
                    }
                    segStart += take; left -= take;
                }

                DateTime day = s.Time.Date;
                if (!heatMon.ContainsKey(day)) { heatMon[day] = new double[24]; heatDown[day] = new double[24]; days.Add(day); }
                heatMon[day][s.Time.Hour] += w[i];
                if (sev == 2) heatDown[day][s.Time.Hour] += w[i];

                // per-check
                CheckAgg[] map;
                if (!schemaMap.TryGetValue(s.Schema, out map))
                {
                    map = new CheckAgg[s.Schema.Defs.Length];
                    for (int c = 0; c < map.Length; c++)
                    {
                        CheckDef d = s.Schema.Defs[c];
                        CheckAgg a;
                        if (!checkByKey.TryGetValue(d.Key, out a))
                        {
                            a = new CheckAgg(); a.Kind = d.Kind; a.Name = d.Name; a.Key = d.Key;
                            a.Service = ctx.Service.Contains(d.Key);
                            checkByKey[d.Key] = a; checks.Add(a);
                            if (d.Kind == "HTTP") latency[d.Key] = new List<int>[nb];
                        }
                        map[c] = a;
                    }
                    schemaMap[s.Schema] = map;
                }
                int bucket = Math.Min(nb - 1, Math.Max(0, (int)Math.Floor((s.Time - t0).TotalSeconds / step)));
                int httpSum = 0, httpN = 0;
                string inspectedNow = "|" + (s.Inspected ?? "") + "|";
                // This round's evidence for or against an HTTPS inspection fault.
                int rInspFail = 0, rInspOk = 0, rOtherFail = 0, rOtherOk = 0;
                bool rDirectOk = false, rDirectTested = false, rDnsOk = false, rDnsTested = false, rGwOk = false, rGwTested = false;
                for (int c = 0; c < map.Length; c++)
                {
                    CheckResult r = s.R[c];
                    if (!r.Tested) continue;
                    CheckAgg a = map[c];
                    a.Tests++;
                    if (a.Kind == "TCP") { rDirectTested = true; if (r.Ok) rDirectOk = true; }
                    else if (a.Kind == "DNS") { rDnsTested = true; rDnsOk = r.Ok; }
                    else if (a.Kind == "GW") { rGwTested = true; rGwOk = r.Ok; }
                    else if (a.Kind == "HTTP")
                    {
                        bool decrypted = inspectedNow.IndexOf("|" + a.Name + "|", StringComparison.Ordinal) >= 0;
                        if (decrypted) { a.InspectedTests++; if (!r.Ok) a.InspectedFails++; }
                        if (!a.Service)
                        {
                            if (decrypted) { if (r.Ok) rInspOk++; else rInspFail++; }
                            else { if (r.Ok) rOtherOk++; else rOtherFail++; }
                        }
                        if (r.Ok)
                        {
                            if (r.DnsMs >= 0) a.Dns.Add(r.DnsMs);
                            if (r.TcpMs >= 0) a.Tcp.Add(r.TcpMs);
                            if (r.TlsMs >= 0) a.Tls.Add(r.TlsMs);
                            if (r.Ms > 1000) a.Slow++;
                        }
                        else
                        {
                            string stage = StageOf(r.Detail);
                            if (stage == "lookup") a.FailLookup++; else if (stage == "connect") a.FailConnect++;
                            else if (stage == "handshake") a.FailHandshake++; else if (stage == "reply") a.FailReply++; else a.FailOther++;
                            if (decrypted && !a.Service)
                            {
                                inspFailTotal++;
                                if (stage == "handshake") { inspFailHandshake++; if (r.TcpMs >= 0) inspFailTcpMs.Add(r.TcpMs); }
                            }
                        }
                    }
                    if (r.Ok)
                    {
                        a.Ok++; a.Ms.Add(r.Ms);
                        if (a.Kind == "HTTP")
                        {
                            List<int>[] lb = latency[a.Key];
                            if (lb[bucket] == null) lb[bucket] = new List<int>();
                            lb[bucket].Add(r.Ms);
                            if (!a.Service) { httpSum += r.Ms; httpN++; }
                        }
                    }
                    else
                    {
                        int cnt; a.Fails.TryGetValue(r.Detail ?? "FAIL", out cnt); a.Fails[r.Detail ?? "FAIL"] = cnt + 1;
                    }
                }
                if (httpN > 0) allHttpMs.Add(httpSum / httpN);

                if (inspectedNow.Length > 2) inspRounds++;
                if (rInspFail > 0)
                {
                    inspFailRounds++;
                    if (rInspOk == 0) inspAllFailRounds++;
                    if (rOtherOk + rOtherFail > 0) { inspRoundsWithControl++; if (rOtherFail == 0) inspRoundsControlOk++; }
                    if (rDirectTested) { inspRoundsDirectTested++; if (rDirectOk) inspRoundsDirectOk++; }
                    if (rDnsTested) { inspRoundsDnsTested++; if (rDnsOk) inspRoundsDnsOk++; }
                    if (rGwTested) { inspRoundsGwTested++; if (rGwOk) inspRoundsGwOk++; }
                }

                // One website failing while another still answers: followed site by site, as episodes.
                for (int c = 0; c < map.Length; c++)
                {
                    CheckAgg a = map[c];
                    if (a.Kind != "HTTP" || a.Service) continue;
                    CheckResult r = s.R[c];
                    if (r.Tested && !r.Ok && httpN > 0)
                    {
                        a.SoloFails++;
                        string why = r.Detail ?? "FAIL";
                        int prior; a.SoloDetails.TryGetValue(why, out prior); a.SoloDetails[why] = prior + 1;
                        if (!a.InEpisode) { a.InEpisode = true; a.Episodes++; a.EpisodeStarts.Add(s.Time); a.CurStart = s.Time; a.CurSec = 0; }
                        a.CurSec += w[i];
                        a.SoloSec += w[i];
                        if (a.CurSec > a.LongestSec) { a.LongestSec = a.CurSec; a.LongestAt = a.CurStart; }
                    }
                    else a.InEpisode = false;
                    if (gapAfter) a.InEpisode = false;
                }

                // incidents: an unbroken run of samples of the same kind (outage, or degraded).
                // A degraded spell that turns into an outage is two entries, so that outage
                // durations are never padded with time when browsing still partly worked.
                if (sev > 0)
                {
                    if (open != null && open.Sev != sev) open = null;
                    if (open == null) { open = new Incident(); open.Start = s.Time; open.Sev = sev; open.StartIndex = i; incidents.Add(open); }
                    int sc; open.StatusCounts.TryGetValue(s.Status, out sc); open.StatusCounts[s.Status] = sc + 1;
                    for (int c = 0; c < map.Length; c++)
                    {
                        CheckResult r = s.R[c];
                        if (!r.Tested || r.Ok) continue;
                        string k = KindShort(map[c].Kind) + (map[c].Kind == "HTTP" || map[c].Kind == "TCP" ? " " + map[c].Name : "") + ": " + r.Detail;
                        int fc; open.FailCounts.TryGetValue(k, out fc); open.FailCounts[k] = fc + 1;
                    }
                    open.Sec += w[i];
                    open.End = s.Time.AddSeconds(w[i]);
                    if (gapAfter) open = null;
                    else if (i == n - 1) open.Ongoing = true;
                }
                else open = null;
            }

            // ---- incident roll-up ---------------------------------------------------
            int outages = 0, degradedCount = 0;
            double longest = 0; DateTime longestAt = DateTime.MinValue;
            foreach (Incident inc in incidents)
            {
                string best = St.Degraded; int bestN = -1;
                foreach (KeyValuePair<string, int> kv in inc.StatusCounts)
                {
                    if (St.Severity(kv.Key) == 2 && kv.Value > bestN) { best = kv.Key; bestN = kv.Value; }
                }
                inc.Code = best;
                causeCount[best] = (causeCount.ContainsKey(best) ? causeCount[best] : 0) + 1;
                if (St.Severity(best) == 2)
                {
                    outages++;
                    if (inc.Sec > longest) { longest = inc.Sec; longestAt = inc.Start; }
                }
                else degradedCount++;
            }

            double downSec = 0, degSec = 0;
            foreach (KeyValuePair<string, double> kv in statusSec)
            {
                int sev = St.Severity(kv.Key);
                if (sev == 2) downSec += kv.Value; else if (sev == 1) degSec += kv.Value;
            }
            double availability = monitored > 0 ? 100.0 * (monitored - downSec) / monitored : 100.0;

            allHttpMs.Sort();
            bool multiDay = start.Date != end.Date;
            string tf = multiDay ? "d MMM HH:mm:ss" : "HH:mm:ss";

            // ---- output: summary ------------------------------------------------------
            Dictionary<string, object> summary = new Dictionary<string, object>();
            summary["start"] = start.ToString("ddd d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
            summary["end"] = end.ToString("ddd d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
            summary["monitored"] = Duration(monitored);
            summary["monitoredSec"] = Math.Round(monitored, 1);
            summary["availability"] = Math.Round(availability, availability >= 99.9 && availability < 100 ? 3 : 2);
            summary["samples"] = n;
            summary["outages"] = outages;
            summary["downtime"] = Duration(downSec);
            summary["downSec"] = Math.Round(downSec, 1);
            summary["longest"] = outages > 0 ? Duration(longest) : "-";
            summary["longestAt"] = outages > 0 ? longestAt.ToString(tf, CultureInfo.InvariantCulture) : "";
            summary["degraded"] = Duration(degSec);
            summary["degradedSec"] = Math.Round(degSec, 1);
            summary["degradedCount"] = degradedCount;
            summary["gap"] = Duration(gapSec);
            summary["gapSec"] = Math.Round(gapSec, 1);
            summary["medianMs"] = allHttpMs.Count > 0 ? (object)(int)Math.Round(Percentile(allHttpMs, 0.5)) : null;
            summary["p95Ms"] = allHttpMs.Count > 0 ? (object)(int)Math.Round(Percentile(allHttpMs, 0.95)) : null;
            data["summary"] = summary;

            // ---- output: causes (downtime by conclusion) ------------------------------
            List<object> causes = new List<object>();
            string topCause = null; double topCauseSec = 0;
            foreach (string code in St.All)
            {
                if (code == St.Online || statusSec[code] <= 0) continue;
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["code"] = code; o["label"] = St.Label(code); o["sev"] = St.Severity(code);
                o["sec"] = Math.Round(statusSec[code], 1); o["dur"] = Duration(statusSec[code]); o["count"] = causeCount[code];
                causes.Add(o);
                if (St.Severity(code) == 2 && statusSec[code] > topCauseSec) { topCauseSec = statusSec[code]; topCause = code; }
            }
            data["causes"] = causes;

            // ---- output: timeline -----------------------------------------------------
            Dictionary<string, object> timeline = new Dictionary<string, object>();
            timeline["t0"] = Epoch(t0);
            timeline["step"] = step;
            timeline["on"] = RoundAll(bOn);
            timeline["deg"] = RoundAll(bDeg);
            timeline["down"] = RoundAll(bDown);
            string[] bTop = new string[nb];
            for (int b = 0; b < nb; b++)
            {
                if (bCause[b] == null) continue;
                double best = -1;
                foreach (KeyValuePair<string, double> kv in bCause[b])
                {
                    // an outage always outranks "degraded" as the headline for a bucket
                    double score = kv.Value + (St.Severity(kv.Key) == 2 ? 1e9 : 0);
                    if (score > best) { best = score; bTop[b] = kv.Key; }
                }
            }
            timeline["cause"] = bTop;
            List<object> series = new List<object>();
            foreach (CheckAgg a in checks)
            {
                if (a.Kind != "HTTP" || a.Service) continue;      // service checks are too sparse to chart
                object[] med = new object[nb];
                List<int>[] lb = latency[a.Key];
                for (int b = 0; b < nb; b++)
                {
                    if (lb[b] == null || lb[b].Count == 0) continue;
                    lb[b].Sort();
                    med[b] = (int)Math.Round(Percentile(lb[b], 0.5));
                }
                Dictionary<string, object> o = new Dictionary<string, object>();
                string sreg; ctx.Regions.TryGetValue(a.Key, out sreg);
                o["name"] = a.Name + (sreg == "UK" ? " (UK)" : ""); o["med"] = med;
                series.Add(o);
            }
            timeline["series"] = series;
            data["timeline"] = timeline;

            // ---- output: checks table -------------------------------------------------
            List<object> checkRows = new List<object>();
            List<string> neverOk = new List<string>();
            List<string> serviceNotes = new List<string>();
            bool directNeverOk = true, anyDirect = false;
            foreach (CheckAgg a in checks)
            {
                if (a.Tests == 0) continue;
                a.Ms.Sort();
                string topFail = ""; int topN = 0;
                foreach (KeyValuePair<string, int> kv in a.Fails) { if (kv.Value > topN) { topN = kv.Value; topFail = kv.Key; } }
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["kind"] = a.Service ? "Service check" : new CheckDef(a.Kind, a.Name, "").KindLabel;
                o["name"] = a.Kind == "HTTP" || a.Kind == "TCP" ? a.Name : "";
                string target; ctx.Targets.TryGetValue(a.Key, out target);
                o["target"] = target ?? "";
                string region; ctx.Regions.TryGetValue(a.Key, out region);
                o["region"] = region ?? "";
                o["tests"] = a.Tests;
                o["okPct"] = Math.Round(100.0 * a.Ok / a.Tests, 2);
                o["fails"] = a.Tests - a.Ok;
                o["med"] = a.Ms.Count > 0 ? (object)(int)Math.Round(Percentile(a.Ms, 0.5)) : null;
                o["p95"] = a.Ms.Count > 0 ? (object)(int)Math.Round(Percentile(a.Ms, 0.95)) : null;
                o["max"] = a.Ms.Count > 0 ? (object)a.Ms[a.Ms.Count - 1] : null;
                o["topFail"] = topN > 0 ? topFail + " (" + topN + ")" : "";
                o["slow"] = a.Kind == "HTTP" ? (object)a.Slow : null;
                checkRows.Add(o);
                if (a.Kind == "HTTP" && !a.Service && a.Ok == 0 && a.Tests >= 5) neverOk.Add(a.Name);
                if (a.Service && a.Tests > a.Ok)
                    serviceNotes.Add(a.Name + " did not answer " + (a.Tests - a.Ok) + " of its " + a.Tests + " checks (most often: " + topFail
                        + "). It is tested as a service in its own right and does not affect the availability figures.");
                if (a.Kind == "TCP") { anyDirect = true; if (a.Ok > 0) directNeverOk = false; }
            }
            data["checks"] = checkRows;

            // ---- output: websites that failed while the connection stayed up ----------
            List<object> siteRows = new List<object>();
            List<string> siteNotes = new List<string>();
            List<string> troubled = new List<string>();
            foreach (CheckAgg a in checks)
            {
                if (a.Kind != "HTTP" || a.Service || a.SoloFails == 0 || a.Ok == 0) continue;
                if (a.Inspected && statusSec[St.Inspection] > 0) continue;
                string topWhy = ""; int topWhyN = 0;
                foreach (KeyValuePair<string, int> kv in a.SoloDetails) { if (kv.Value > topWhyN) { topWhyN = kv.Value; topWhy = kv.Key; } }
                double pct = 100.0 * a.SoloFails / a.Tests;
                string pctText = (pct < 0.1 ? "under 0.1" : pct.ToString("0.#", CultureInfo.InvariantCulture)) + "%";
                double cycle = RegularCycle(a.EpisodeStarts, Math.Max(30, 4 * slowest / 1000.0));

                Dictionary<string, object> o = new Dictionary<string, object>();
                o["name"] = a.Name;
                o["fails"] = a.SoloFails;
                o["tests"] = a.Tests;
                o["pct"] = pctText;
                o["episodes"] = a.Episodes;
                o["dur"] = Duration(a.SoloSec);
                o["longest"] = Duration(a.LongestSec);
                o["longestAt"] = a.LongestAt.ToString(tf, CultureInfo.InvariantCulture);
                o["why"] = FailWords(topWhy);
                o["cycle"] = cycle > 0 ? "about every " + About(cycle) : "";
                siteRows.Add(o);

                // Worth a sentence in the findings only when it is more than the odd lost request.
                if (a.SoloFails < 3 || (a.SoloFails * 200 < a.Tests && a.Episodes < 3)) continue;
                troubled.Add(a.Name);
                string note = a.Name + " failed " + a.SoloFails.ToString("N0", CultureInfo.InvariantCulture) + " of its "
                    + a.Tests.ToString("N0", CultureInfo.InvariantCulture) + " checks (" + pctText + ", mostly: " + FailWords(topWhy)
                    + ") while other websites were still answering. That happened in " + a.Episodes + (a.Episodes == 1 ? " episode" : " separate episodes")
                    + " totalling " + Duration(a.SoloSec) + "; the longest lasted " + Duration(a.LongestSec) + ", starting at "
                    + a.LongestAt.ToString(tf, CultureInfo.InvariantCulture) + ". The connection itself was up, so this is not counted as an outage, but anything that relies on "
                    + a.Name + " would have been slow or unreachable at those moments.";
                if (cycle > 0)
                    note += " The episodes recur on a regular cycle of about " + About(cycle) + ". A pattern that regular points at something that runs on a timer "
                        + "(a firewall or web filter refreshing its rules or address lists, a scheduled job, a DNS record being renewed) rather than a random fault on the line.";
                siteNotes.Add(note);
            }
            if (siteRows.Count > 0) data["sites"] = siteRows;

            // ---- output: HTTPS inspection, and where each web request spends its time ----
            // Latest certificate seen for each check, and every distinct filter certificate.
            Dictionary<string, CertRecord> certByCheck = new Dictionary<string, CertRecord>();
            List<string> filterIssuers = new List<string>();
            List<object> certRows = new List<object>();
            foreach (CertRecord cr in ctx.Certs)
            {
                certByCheck[cr.Check] = cr;
                string shortIssuer = CertInfo.ShortName(cr.Issuer);
                if (cr.Inspected && !filterIssuers.Contains(shortIssuer)) filterIssuers.Add(shortIssuer);
                if (certRows.Count < 60)
                    certRows.Add(new string[] { cr.Time.ToString("d MMM HH:mm:ss", CultureInfo.InvariantCulture), cr.Check, cr.Host, cr.Adapter,
                        cr.Inspected ? "Decrypted by filter" : "Site's own", cr.Issuer, cr.Inspected ? cr.Why : "" });
            }
            List<object> stageRows = new List<object>();
            List<string> decryptedNames = new List<string>(), plainNames = new List<string>();
            int decTests = 0, decFails = 0, plainTests = 0, plainFails = 0;
            bool anyStage = false;
            foreach (CheckAgg a in checks)
            {
                if (a.Kind != "HTTP" || a.Tests == 0) continue;
                a.Dns.Sort(); a.Tcp.Sort(); a.Tls.Sort();
                if (a.Tcp.Count > 0) anyStage = true;
                CertRecord cr; certByCheck.TryGetValue(a.Name, out cr);
                string targetUrl; ctx.Targets.TryGetValue(a.Key, out targetUrl);
                bool plainHttp = targetUrl != null && targetUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
                bool decrypted = a.Inspected;
                if (!a.Service)
                {
                    if (decrypted) { decryptedNames.Add(a.Name); decTests += a.Tests; decFails += a.Tests - a.Ok; }
                    else { plainNames.Add(a.Name); plainTests += a.Tests; plainFails += a.Tests - a.Ok; }
                }
                List<string> at = new List<string>();
                if (a.FailLookup > 0) at.Add("name lookup " + a.FailLookup);
                if (a.FailConnect > 0) at.Add("connecting " + a.FailConnect);
                if (a.FailHandshake > 0) at.Add("secure handshake " + a.FailHandshake);
                if (a.FailReply > 0) at.Add("waiting for reply " + a.FailReply);
                if (a.FailOther > 0) at.Add("other " + a.FailOther);
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["name"] = a.Name + (a.Service ? " (service check)" : "");
                o["decrypted"] = decrypted;
                o["cert"] = plainHttp ? "None (plain HTTP, not encrypted)" : decrypted && cr != null ? CertInfo.ShortName(cr.Issuer)
                          : cr != null ? CertInfo.ShortName(cr.Issuer) : decrypted ? "A web filter's" : "Not recorded";
                o["tests"] = a.Tests;
                o["fails"] = a.Tests - a.Ok;
                o["slow"] = a.Slow;
                o["dns"] = a.Dns.Count > 0 ? (object)(int)Math.Round(Percentile(a.Dns, 0.5)) : null;
                o["tcp"] = a.Tcp.Count > 0 ? (object)(int)Math.Round(Percentile(a.Tcp, 0.5)) : null;
                o["tls"] = a.Tls.Count > 0 ? (object)(int)Math.Round(Percentile(a.Tls, 0.5)) : null;
                o["tlsMax"] = a.Tls.Count > 0 ? (object)a.Tls[a.Tls.Count - 1] : null;
                o["failedAt"] = string.Join(", ", at.ToArray());
                stageRows.Add(o);
            }

            List<string> inspectionNotes = new List<string>();
            List<string> proof = new List<string>();
            bool inspectionActive = decryptedNames.Count > 0;
            if (inspectionActive)
            {
                string who = filterIssuers.Count > 0 ? "\u201c" + string.Join("\u201d, \u201c", filterIssuers.ToArray()) + "\u201d" : "a web filter";
                inspectionNotes.Add("This connection decrypts secure (HTTPS) traffic. The certificate" + (decryptedNames.Count == 1 ? " for " : "s for ")
                    + List(decryptedNames) + (decryptedNames.Count == 1 ? " was" : " were") + " issued by " + who + " rather than by "
                    + (decryptedNames.Count == 1 ? "the site\u2019s" : "the sites\u2019") + " own certificate authority, which is how HTTPS inspection by a web filter shows itself."
                    + (plainNames.Count > 0 ? " " + List(plainNames) + (plainNames.Count == 1 ? " is" : " are") + " not decrypted, which gives a comparison." : ""));
                if (decFails > 0)
                {
                    proof.Add("Decrypted sites (" + List(decryptedNames) + ") failed " + decFails.ToString("N0", CultureInfo.InvariantCulture) + " of "
                        + decTests.ToString("N0", CultureInfo.InvariantCulture) + " checks."
                        + (plainTests > 0 ? " Sites that are not decrypted (" + List(plainNames) + ") failed " + plainFails.ToString("N0", CultureInfo.InvariantCulture)
                            + " of " + plainTests.ToString("N0", CultureInfo.InvariantCulture) + "." : ""));
                    if (inspFailRounds > 0)
                    {
                        if (inspRoundsWithControl > 0)
                            proof.Add("In " + Of(inspRoundsControlOk, inspRoundsWithControl) + " rounds in which a decrypted site failed, every site that is not decrypted loaded normally at the same moment.");
                        proof.Add("In " + Of(inspAllFailRounds, inspFailRounds) + " of those rounds, all the decrypted sites failed together.");
                        List<string> under = new List<string>();
                        if (inspRoundsDirectTested > 0) under.Add("a direct connection to the internet was made in " + Of(inspRoundsDirectOk, inspRoundsDirectTested));
                        if (inspRoundsDnsTested > 0) under.Add("the DNS server answered in " + Of(inspRoundsDnsOk, inspRoundsDnsTested));
                        if (inspRoundsGwTested > 0) under.Add("the gateway replied in " + Of(inspRoundsGwOk, inspRoundsGwTested));
                        if (under.Count > 0) proof.Add("The network underneath was working: in the same rounds, " + string.Join("; ", under.ToArray()) + ".");
                    }
                    if (inspFailHandshake > 0)
                    {
                        inspFailTcpMs.Sort();
                        string share = Of(inspFailHandshake, inspFailTotal);
                        proof.Add(char.ToUpperInvariant(share[0]) + share.Substring(1) + " failures happened during the secure handshake, after the connection itself had been made"
                            + (inspFailTcpMs.Count > 0 ? " (typically in " + (int)Math.Round(Percentile(inspFailTcpMs, 0.5)) + " ms)" : "")
                            + ". A line fault stops the connection being made at all; a connection that is made at once and then never completes its handshake "
                            + "is waiting on whatever is decrypting it.");
                    }
                    bool strong = inspFailRounds >= 3 && (inspRoundsWithControl == 0 || inspRoundsControlOk * 10 >= inspRoundsWithControl * 9)
                        && (plainTests == 0 || plainFails * 20 <= plainTests) && decFails * 1000 >= decTests;
                    if (strong)
                        inspectionNotes.Add("The failures in this period follow the pattern of a fault in that HTTPS inspection, not in the internet line: decrypted sites failed "
                            + decFails.ToString("N0", CultureInfo.InvariantCulture) + " times while sites that are not decrypted"
                            + (plainTests > 0 ? " failed " + plainFails.ToString("N0", CultureInfo.InvariantCulture) + " times" : " were not available to compare")
                            + (inspFailHandshake > 0 ? ", and " + Of(inspFailHandshake, inspFailTotal) + " failures were in the secure handshake after the connection had already been made" : "")
                            + ". The section \u201cHTTPS inspection\u201d sets out the evidence.");

                    // Do the faults come round on a timer?
                    List<DateTime> faultStarts = new List<DateTime>();
                    foreach (Incident inc in incidents) { if (inc.Code == St.Inspection) faultStarts.Add(inc.Start); }
                    double faultCycle = RegularCycle(faultStarts, Math.Max(30, 4 * slowest / 1000.0));
                    if (faultCycle > 0)
                    {
                        string rhythm = "The HTTPS inspection faults recur on a regular cycle of about " + About(faultCycle)
                            + ". A pattern that regular points at something on the filter that runs on a timer (a reload of its rules or block lists, "
                            + "a directory or sign-in refresh, a logging job) rather than a random fault.";
                        inspectionNotes.Add(rhythm);
                        proof.Add(rhythm);
                    }
                }
            }
            if (stageRows.Count > 0 && (inspectionActive || anyStage))
            {
                Dictionary<string, object> insp = new Dictionary<string, object>();
                insp["active"] = inspectionActive;
                insp["issuers"] = filterIssuers;
                insp["sites"] = stageRows;
                insp["proof"] = proof;
                insp["certLog"] = certRows;
                insp["timeout"] = (ctx.TimeoutMs / 1000.0).ToString("0.#", CultureInfo.InvariantCulture);
                data["inspection"] = insp;
            }

            // ---- output: public IP address ---------------------------------------------
            meta["publicIp"] = lastIp;
            meta["publicIpOthers"] = Math.Max(0, ipList.Count - 1);
            if (ipList.Count > 0)
            {
                List<object> ipRows = new List<object>();
                foreach (IpAgg ia in ipList)
                {
                    Dictionary<string, object> o = new Dictionary<string, object>();
                    o["ip"] = ia.Ip;
                    o["current"] = ia.Ip == lastIp;
                    o["first"] = ia.First.ToString(tf, CultureInfo.InvariantCulture);
                    o["last"] = ia.Last.ToString(tf, CultureInfo.InvariantCulture);
                    o["dur"] = Duration(ia.Sec);
                    o["down"] = ia.DownSec > 0 ? Duration(ia.DownSec) : "none";
                    o["deg"] = ia.DegSec >= 1 ? Duration(ia.DegSec) : "none";
                    ipRows.Add(o);
                }
                data["ips"] = ipRows;
                data["ipChangeCount"] = ipChangeCount;
                if (ipChanges.Count > 40) ipChanges = ipChanges.GetRange(ipChanges.Count - 40, 40);
                ipChanges.Reverse();
                data["ipChanges"] = ipChanges;
            }

            // ---- output: incidents ----------------------------------------------------
            List<object> incRows = new List<object>();
            int first = Math.Max(0, incidents.Count - MaxIncidentRows);
            for (int i = incidents.Count - 1; i >= first; i--)
            {
                Incident inc = incidents[i];
                List<KeyValuePair<string, int>> fl = new List<KeyValuePair<string, int>>(inc.FailCounts);
                fl.Sort(delegate(KeyValuePair<string, int> x, KeyValuePair<string, int> y) { return y.Value.CompareTo(x.Value); });
                StringBuilder sb = new StringBuilder();
                for (int k = 0; k < fl.Count && k < 4; k++)
                {
                    if (k > 0) sb.Append("; ");
                    sb.Append(fl[k].Key);
                    if (fl[k].Value > 1) sb.Append(" ×").Append(fl[k].Value);
                }
                if (fl.Count > 4) sb.Append("; …");
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["start"] = inc.Start.ToString(tf, CultureInfo.InvariantCulture);
                o["end"] = inc.Ongoing ? "still ongoing" : inc.End.ToString(tf, CultureInfo.InvariantCulture);
                o["dur"] = Duration(inc.Sec);
                o["code"] = inc.Code;
                o["detail"] = sb.ToString();
                incRows.Add(o);
            }
            data["incidents"] = incRows;
            data["incidentsTotal"] = incidents.Count;

            // ---- output: heat map (only worth drawing for longer runs) -----------------
            if (span >= 2 * 3600)
            {
                days.Sort();
                if (days.Count > 31) days = days.GetRange(days.Count - 31, 31);
                List<object> rows = new List<object>();
                foreach (DateTime d in days)
                {
                    object[] cells = new object[24];
                    for (int h = 0; h < 24; h++)
                    {
                        if (heatMon[d][h] < 1) continue;
                        cells[h] = new double[] { Math.Round(heatMon[d][h]), Math.Round(heatDown[d][h], 1) };
                    }
                    Dictionary<string, object> o = new Dictionary<string, object>();
                    o["day"] = d.ToString("ddd d MMM", CultureInfo.InvariantCulture);
                    o["cells"] = cells;
                    rows.Add(o);
                }
                data["heat"] = rows;
            }

            // ---- output: plain-English findings ----------------------------------------
            List<string> verdict = new List<string>();
            string level = "good", headline;
            if (outages == 0 && degSec < monitored * 0.01)
            {
                headline = "No outages detected";
            }
            else if (outages == 0)
            {
                level = "warning"; headline = "No outages, but the connection was degraded at times";
            }
            else if (availability < 99.0 || longest >= 60)
            {
                level = "critical"; headline = outages == 1 ? "1 outage detected" : outages + " outages detected";
            }
            else
            {
                level = "warning"; headline = outages == 1 ? "1 brief outage detected" : outages + " brief outages detected";
            }
            if (outages == 0 && troubled.Count > 0)
            {
                // A site that keeps failing is a finding in its own right, however small its share of the time.
                level = "warning";
                headline = "No outages, but " + (troubled.Count == 1 ? troubled[0] + " was" : string.Join(", ", troubled.GetRange(0, troubled.Count - 1).ToArray())
                    + " and " + troubled[troubled.Count - 1] + " were") + " unreachable at times";
            }

            verdict.Add("Monitored for " + Duration(monitored) + " from " + Environment.MachineName + ". Web access was available for "
                + ((double)summary["availability"]).ToString("0.###", CultureInfo.InvariantCulture) + "% of that time.");
            if (outages > 0)
            {
                verdict.Add((outages == 1 ? "There was 1 outage" : "There were " + outages + " outages") + " totalling " + Duration(downSec)
                    + ". The longest lasted " + Duration(longest) + ", starting at " + longestAt.ToString(tf, CultureInfo.InvariantCulture) + ".");
                if (topCause != null)
                    verdict.Add("Most of the downtime was classed as “" + St.Label(topCause) + "”. " + St.Explain(topCause));
            }
            if (degSec >= 1)
                verdict.Add("The connection was degraded (some web checks failing, others working) for " + Duration(degSec)
                    + " across " + degradedCount + (degradedCount == 1 ? " episode." : " episodes."));
            foreach (string note in inspectionNotes) verdict.Add(note);
            foreach (string note in siteNotes) verdict.Add(note);
            if (ipList.Count == 1)
                verdict.Add("The public IP address was " + lastIp + " throughout.");
            else if (ipList.Count > 1)
            {
                List<string> seenIps = new List<string>();
                foreach (IpAgg ia in ipList) seenIps.Add(ia.Ip);
                if (seenIps.Count > 6) { int extra = seenIps.Count - 6; seenIps = seenIps.GetRange(0, 6); seenIps.Add("+" + extra + " more"); }
                verdict.Add("The public IP address changed " + ipChangeCount + (ipChangeCount == 1 ? " time" : " times") + " (" + string.Join(", ", seenIps.ToArray())
                    + "; now " + lastIp + "). A change of public address usually means the line reconnected, or traffic moved to a different line or exit point.");
            }
            if (adapters.Count > 1)
                verdict.Add("Checks in this period went out through more than one network adapter (" + Join(adapters)
                    + "), so the figures blend different connections. Compare runs made on one adapter at a time to tell the connections apart.");
            if (neverOk.Count > 0)
                verdict.Add("The web check" + (neverOk.Count == 1 ? " " : "s ") + string.Join(", ", neverOk.ToArray())
                    + " never succeeded. That usually means the site is blocked by filtering policy, so "
                    + (neverOk.Count == 1 ? "it was" : "they were") + " left out of the availability figures.");
            if (anyDirect && directNeverOk)
                verdict.Add("Direct connections to the internet never succeeded, which is normal where a firewall only allows traffic through the proxy. "
                    + "It does mean a proxy fault and an internet-line fault cannot be told apart from this computer.");
            if (gapSec >= 60)
                verdict.Add("There is no data for " + Duration(gapSec) + " of the period (computer asleep, or the monitor not running). Those gaps are not counted as up or down.");
            foreach (string note in serviceNotes) verdict.Add(note);

            // ---- Wi-Fi roll-up -----------------------------------------------------------
            if (anyWifi)
            {
                int suspect = 0;
                foreach (Incident inc in incidents)
                {
                    if (St.Severity(inc.Code) != 2) continue;
                    Sample at = samples[inc.StartIndex];
                    if (at.WifiBssid.Length > 0) { ApAgg ap; if (aps.TryGetValue(at.WifiBssid, out ap)) ap.OutagesBegan++; }
                    bool weak = at.WifiSignal >= 0 && at.WifiSignal < 40;
                    bool moved = false;
                    foreach (int ri in roamIndex)
                    {
                        if (Math.Abs((samples[ri].Time - at.Time).TotalSeconds) <= 10) { moved = true; break; }
                    }
                    if (weak || moved) suspect++;
                }
                List<ApAgg> apList = new List<ApAgg>(aps.Values);
                apList.Sort(delegate(ApAgg x, ApAgg y) { return y.Sec.CompareTo(x.Sec); });
                List<object> apRows = new List<object>();
                for (int k = 0; k < apList.Count && k < 25; k++)
                {
                    ApAgg ap = apList[k];
                    ap.Signal.Sort();
                    Dictionary<string, object> o = new Dictionary<string, object>();
                    o["bssid"] = ap.Bssid; o["ssid"] = ap.Ssid; o["dur"] = Duration(ap.Sec);
                    o["med"] = ap.Signal.Count > 0 ? (object)(int)Math.Round(Percentile(ap.Signal, 0.5)) : null;
                    o["min"] = ap.Signal.Count > 0 ? (object)ap.Signal[0] : null;
                    o["down"] = ap.DownSec > 0 ? Duration(ap.DownSec) : "none";
                    o["outages"] = ap.OutagesBegan;
                    apRows.Add(o);
                }
                List<object> roamRows = new List<object>();
                for (int k = roamIndex.Count - 1; k >= 0 && roamRows.Count < 40; k--)
                {
                    Sample to = samples[roamIndex[k]], fromS = samples[roamIndex[k] - 1];
                    roamRows.Add(new object[] { to.Time.ToString(tf, CultureInfo.InvariantCulture), fromS.WifiBssid,
                        fromS.WifiSignal >= 0 ? fromS.WifiSignal + "%" : "", to.WifiBssid, to.WifiSignal >= 0 ? to.WifiSignal + "%" : "" });
                }
                Dictionary<string, object> wifi = new Dictionary<string, object>();
                wifi["aps"] = apRows; wifi["roams"] = roamIndex.Count; wifi["roamList"] = roamRows; wifi["suspect"] = suspect;
                data["wifi"] = wifi;
                object[] sig = new object[nb];
                for (int b = 0; b < nb; b++) { if (bWifi[b] >= 0) sig[b] = bWifi[b]; }
                timeline["wifi"] = sig;
                timeline["wifiUnit"] = "%"; timeline["wifiMax"] = 100; timeline["wifiLabel"] = "Wi-Fi signal (weakest per slot)";

                if (outages > 0 && suspect > 0)
                    verdict.Add(suspect + " of the " + outages + (outages == 1 ? " outage" : " outages") + " began within 10 seconds of this computer changing "
                        + "access point, or with Wi-Fi signal under 40%. That points at Wi-Fi coverage near this computer rather than the internet line.");
                else if (outages > 0)
                    verdict.Add("Wi-Fi signal was normal and the computer stayed on the same access point when each outage began, so Wi-Fi is unlikely to be the cause.");
            }
            else if (anyLink)
            {
                // No permission for signal strength or access point: fall back on link speed, which needs none.
                object[] link = new object[nb];
                // Median, not minimum: Windows reports a very low figure for a moment whenever the
                // adapter scans for networks, and that is not a real loss of signal.
                for (int b = 0; b < nb; b++)
                {
                    if (bLink[b] == null) continue;
                    bLink[b].Sort();
                    link[b] = (int)Math.Round(Percentile(bLink[b], 0.5));
                }
                int top = 100;
                foreach (int c in new int[] { 100, 200, 400, 600, 1000, 1200, 2000, 2400, 5000, 10000 }) { top = c; if (c >= maxLink) break; }
                timeline["wifi"] = link;
                timeline["wifiUnit"] = " Mbps"; timeline["wifiMax"] = top; timeline["wifiLabel"] = "Wi-Fi link speed (typical per slot)";
                verdict.Add("Wi-Fi signal strength and access point were not recorded" + (ctx.WifiWhyNot.Length > 0 ? " (" + ctx.WifiWhyNot + ")" : "")
                    + ". Wi-Fi link speed is charted instead: it needs no permission, and a sustained drop in it is a sign of weak signal.");
            }

            // ---- route traces --------------------------------------------------------------
            if (ctx.Traces.Count > 0) data["traces"] = TraceRows(ctx.Traces);

            foreach (string note in ctx.Notes) verdict.Add(note);

            data["level"] = level;
            data["headline"] = headline;
            data["verdict"] = verdict;

            // ---- output: environment ---------------------------------------------------
            List<KeyValuePair<string, string>> env = new List<KeyValuePair<string, string>>(ctx.Environment);
            if (localIps.Count > 0) env.Add(new KeyValuePair<string, string>("Local IP address" + (localIps.Count > 1 ? "es" : ""), Join(localIps)));
            if (adapters.Count > 1) env.Add(new KeyValuePair<string, string>("Adapters used in this period", Join(adapters)));
            if (ipList.Count > 0)
            {
                // Insertion-ordered, so the addresses read in the order they were first seen.
                HashSet<string> seen = new HashSet<string>();
                foreach (IpAgg ia in ipList) seen.Add(ia.Ip);
                env.Add(new KeyValuePair<string, string>("Public IP address" + (ipList.Count > 1 ? "es" : ""), Join(seen)));
            }
            env.Add(new KeyValuePair<string, string>("Checks recorded", n.ToString("N0", CultureInfo.InvariantCulture)));
            data["env"] = PairList(env);
            return data;
        }

        private static List<object> TraceRows(List<Trace> traces)
        {
            // Baseline = the most recent healthy trace; outages = the most recent few.
            Trace baseline = null;
            List<Trace> outages = new List<Trace>();
            foreach (Trace t in traces)
            {
                if (t.Reason == "BASELINE") baseline = t; else outages.Add(t);
            }
            List<Trace> show = new List<Trace>();
            if (baseline != null) show.Add(baseline);
            for (int i = Math.Max(0, outages.Count - 8); i < outages.Count; i++) show.Add(outages[i]);

            bool baselineUseful = baseline != null && baseline.LastAnswering >= 2;
            List<object> rows = new List<object>();
            foreach (Trace t in show)
            {
                string summary;
                int last = t.LastAnswering;
                if (t.Reason == "BASELINE")
                {
                    summary = t.Reached ? "Healthy route for comparison: " + t.Target + " answered after " + t.Hops.Count + " hops."
                        : last == 0 ? "Nothing on this network answers route traces, even when healthy, so traces here cannot locate a fault."
                        : "This network only answers route traces as far as hop " + last + ", even when healthy.";
                }
                else if (t.Reached)
                    summary = "The route to " + t.Target + " was still working end to end when this outage began. The fault was not on the path out to the internet, which points at the web filter / proxy.";
                else if (last == 0)
                    summary = "Nothing answered, not even the first hop (this computer's own gateway). That points at the local network or Wi-Fi.";
                else
                {
                    TraceHop lastHop = t.At(last);
                    summary = "Replies stopped after hop " + last + " (" + lastHop.Address + ").";
                    TraceHop next = baselineUseful ? baseline.At(last + 1) : null;
                    if (next != null && next.Address.Length > 0)
                        summary += " When healthy, the next hop is " + next.Address + ", so the fault lies at or beyond that point.";
                    else if (baselineUseful && baseline.LastAnswering > last)
                        summary += " The healthy route answers further out than this, so the fault lies beyond hop " + last + ".";
                    else
                        summary += " The healthy trace does not answer beyond this point either, so this is not conclusive.";
                }
                List<object> hops = new List<object>();
                foreach (TraceHop h in t.Hops) hops.Add(new object[] { h.Hop, h.Address, h.Ms >= 0 ? (object)h.Ms : null });
                Dictionary<string, object> o = new Dictionary<string, object>();
                o["time"] = t.Time.ToString("d MMM HH:mm:ss", CultureInfo.InvariantCulture);
                o["reason"] = t.Reason == "BASELINE" ? "Healthy baseline" : "At start of outage";
                o["outage"] = t.Reason != "BASELINE";
                o["target"] = t.Target; o["summary"] = summary; o["hops"] = hops;
                rows.Add(o);
            }
            return rows;
        }

        /// <summary>
        /// Looks for a regular rhythm in when episodes began. Returns the cycle length in
        /// seconds, or 0 when there is none. Missed beats are allowed for (a gap of two or
        /// three cycles still fits), but most gaps must be a single cycle.
        /// </summary>
        internal static double RegularCycle(List<DateTime> starts, double shortestCycle)
        {
            if (starts.Count < 6) return 0;
            int from = Math.Max(0, starts.Count - 400);
            List<double> gaps = new List<double>();
            for (int i = from + 1; i < starts.Count; i++) gaps.Add((starts[i] - starts[i - 1]).TotalSeconds);
            List<double> sorted = new List<double>(gaps);
            sorted.Sort();
            // At least 40% of gaps must be one cycle long, so the cycle cannot be longer than this.
            double longestCandidate = sorted[Math.Min(sorted.Count - 1, (int)(sorted.Count * 0.6))];

            double tried = -1;
            foreach (double g in sorted)
            {
                if (g < shortestCycle) continue;
                if (g > longestCandidate) break;
                if (tried > 0 && g < tried * 1.05) continue;      // as good as the candidate just tried
                tried = g;
                double tolerance = Math.Max(6, g * 0.05);
                int match = 0, single = 0;
                double sum = 0;
                foreach (double x in gaps)
                {
                    int k = (int)Math.Round(x / g);
                    if (k < 1 || k > 6 || Math.Abs(x - k * g) > tolerance) continue;
                    match++;
                    if (k == 1) single++;
                    sum += x / k;
                }
                if (match * 100 >= gaps.Count * 85 && single * 100 >= gaps.Count * 40) return sum / match;
            }
            return 0;
        }

        private static string About(double sec)
        {
            if (sec < 90) return Math.Round(sec).ToString(CultureInfo.InvariantCulture) + " seconds";
            if (sec < 5400)
            {
                double m = Math.Round(sec / 60 * 2) / 2;
                return m.ToString("0.#", CultureInfo.InvariantCulture) + (m == 1 ? " minute" : " minutes");
            }
            double h = Math.Round(sec / 3600 * 10) / 10;
            return h.ToString("0.#", CultureInfo.InvariantCulture) + (h == 1 ? " hour" : " hours");
        }

        // A failure code from the log in plain words, e.g. TIMEOUT -> "timed out".
        private static string FailWords(string detail)
        {
            string words = MainForm.Friendly(detail ?? "");
            int paren = words.IndexOf(" (");
            if (paren > 0) words = words.Substring(0, paren);
            return words.Length == 0 ? "failed" : (words == detail ? words : words.ToLowerInvariant());
        }

        // Which stage of a web request a failure code belongs to.
        internal static string StageOf(string detail)
        {
            switch (detail ?? "")
            {
                case "DNS_FAIL": case "DNS_TIMEOUT": case "PROXY_DNS_FAIL": return "lookup";
                case "CONNECT_FAIL": case "CONNECT_TIMEOUT": case "REFUSED": case "UNREACHABLE": return "connect";
                case "TLS_TIMEOUT": case "TLS_RESET": case "TLS_ERROR": return "handshake";
                case "RESPONSE_TIMEOUT": case "CONNECTION_RESET": return "reply";
                default: return "other";
            }
        }

        private static string Of(int part, int whole)
        {
            return part == whole ? (whole == 1 ? "the 1" : "all " + whole.ToString("N0", CultureInfo.InvariantCulture))
                : part.ToString("N0", CultureInfo.InvariantCulture) + " of the " + whole.ToString("N0", CultureInfo.InvariantCulture);
        }

        private static string List(List<string> names)
        {
            if (names.Count == 0) return "";
            if (names.Count == 1) return names[0];
            return string.Join(", ", names.GetRange(0, names.Count - 1).ToArray()) + " and " + names[names.Count - 1];
        }

        private static string Join(HashSet<string> set)
        {
            List<string> l = new List<string>(set);
            if (l.Count > 6) { int extra = l.Count - 6; l = l.GetRange(0, 6); l.Add("+" + extra + " more"); }
            return string.Join(", ", l.ToArray());
        }

        private static List<object> PairList(List<KeyValuePair<string, string>> pairs)
        {
            List<object> l = new List<object>();
            foreach (KeyValuePair<string, string> kv in pairs) l.Add(new string[] { kv.Key, kv.Value });
            return l;
        }

        private static double[] RoundAll(double[] a)
        {
            double[] r = new double[a.Length];
            for (int i = 0; i < a.Length; i++) r[i] = Math.Round(a[i], 1);
            return r;
        }
    }
}
