// Internet Monitor - sampling engine, diagnosis and CSV log store.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace InternetMonitor
{
    internal enum Tri { NA, Ok, Fail }

    internal static class Diagnosis
    {
        /// <summary>
        /// Turns one round of check results into a single conclusion.
        /// Pure function: everything it needs is passed in.
        /// </summary>
        /// <param name="httpOk">Web checks that succeeded (policy-blocked ones excluded).</param>
        /// <param name="httpCounted">Web checks that count.</param>
        /// <param name="gateway">NA when the gateway never answers pings on this network.</param>
        /// <param name="direct">NA when direct connections are not permitted on this network.</param>
        public static string Classify(bool linkUp, int httpOk, int httpCounted, Tri gateway, Tri dns, Tri proxy, Tri direct, bool explicitProxy)
        {
            if (httpCounted > 0 && httpOk >= httpCounted) return St.Online;
            if (httpOk > 0) return St.Degraded;

            // Every web check failed. Work outwards from this computer.
            if (!linkUp) return St.NoNetwork;
            if (gateway == Tri.Fail) return St.LocalNetwork;
            if (explicitProxy && proxy == Tri.Fail) return St.Proxy;
            if (direct == Tri.Ok)
            {
                if (!explicitProxy && dns == Tri.Fail) return St.Dns;
                return St.Proxy;
            }
            if (direct == Tri.Fail) return St.InternetDown;
            if (!explicitProxy && dns == Tri.Fail) return St.Dns;
            return St.WebDown;
        }
    }

    // ------------------------------------------------------------------
    // Where files go, and the CSV log itself
    // ------------------------------------------------------------------
    internal sealed class LogStore : IDisposable
    {
        public readonly string Root;
        public readonly string LogDir;
        public readonly string ReportDir;
        public readonly string RootNote;
        public string LastError;
        public string CurrentFile;

        private StreamWriter writer;
        private string writerDate;
        private string writerHeader;
        private readonly object gate = new object();
        private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

        public LogStore(Settings settings, string exeDir)
        {
            string note = "";
            string root = null;

            if (settings.DataFolder.Length > 0)
            {
                if (IsWritable(settings.DataFolder)) root = settings.DataFolder;
                else note = "The folder in InternetMonitor.ini (" + settings.DataFolder + ") is not writable. ";
            }
            if (root == null)
            {
                if (IsWritable(exeDir)) root = exeDir;
                else note += "The program folder is read-only, so files are saved in your Documents folder instead.";
            }
            if (root == null)
            {
                root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "InternetMonitor");
                if (!IsWritable(root))
                {
                    root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "InternetMonitor");
                    IsWritable(root);
                }
            }
            Root = root;
            RootNote = note.Trim();
            LogDir = Path.Combine(root, "Logs");
            ReportDir = Path.Combine(root, "Reports");
            try { Directory.CreateDirectory(LogDir); Directory.CreateDirectory(ReportDir); } catch { }
        }

        private static bool IsWritable(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                string probe = Path.Combine(dir, ".write-test-" + Guid.NewGuid().ToString("N") + ".tmp");
                File.WriteAllText(probe, "x");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }

        public static string MachineTag
        {
            get { return Regex.Replace(Environment.MachineName, "[^A-Za-z0-9_-]", "_"); }
        }

        private static string Header(Schema schema)
        {
            StringBuilder sb = new StringBuilder("Timestamp,Status,IntervalMs");
            foreach (CheckDef d in schema.Defs) sb.Append(',').Append(d.Key).Append("_Result,").Append(d.Key).Append("_ms");
            sb.Append(",LocalIP,ExternalIP,WiFi_SSID,WiFi_BSSID,WiFi_Signal,WiFi_LinkMbps");
            return sb.ToString();
        }

        public void Append(Sample s)
        {
            lock (gate)
            {
                try
                {
                    string date = s.Time.ToString("yyyy-MM-dd");
                    string header = Header(s.Schema);
                    if (writer == null || date != writerDate || header != writerHeader) Open(date, header);

                    StringBuilder sb = new StringBuilder(160);
                    sb.Append(s.Time.ToString(TimeFormat, CultureInfo.InvariantCulture)).Append(',').Append(s.Status).Append(',').Append(s.IntervalMs);
                    foreach (CheckResult r in s.R)
                    {
                        sb.Append(',');
                        if (r.Tested) sb.Append(r.Ok ? "OK" : r.Detail);
                        sb.Append(',');
                        if (r.Tested && r.Ok) sb.Append(r.Ms);
                    }
                    sb.Append(',').Append(s.LocalIP).Append(',').Append(s.ExternalIP);
                    sb.Append(',').Append(s.WifiSsid).Append(',').Append(s.WifiBssid).Append(',');
                    if (s.WifiSignal >= 0) sb.Append(s.WifiSignal);
                    sb.Append(',');
                    if (s.WifiLinkMbps >= 0) sb.Append(s.WifiLinkMbps);
                    writer.WriteLine(sb.ToString());
                    LastError = null;
                }
                catch (Exception ex)
                {
                    // A dropped network share must not stop the monitoring. The session is
                    // also held in memory, and the file is reopened on the next sample.
                    LastError = ex.Message;
                    CloseWriter();
                }
            }
        }

        private void Open(string date, string header)
        {
            CloseWriter();
            string baseName = "InternetLog_" + MachineTag + "_" + date;
            for (int n = 1; n < 100; n++)
            {
                string path = Path.Combine(LogDir, baseName + (n == 1 ? "" : "_" + n) + ".csv");
                bool exists = File.Exists(path) && new FileInfo(path).Length > 0;
                if (exists)
                {
                    // Only continue a file whose columns match (the check list may have been edited).
                    string first = null;
                    try
                    {
                        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (StreamReader sr = new StreamReader(fs)) first = sr.ReadLine();
                    }
                    catch { }
                    if (first != header) continue;
                }
                FileStream outFs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                writer = new StreamWriter(outFs, new UTF8Encoding(false));
                writer.AutoFlush = true;
                if (!exists) writer.WriteLine(header);
                writerDate = date;
                writerHeader = header;
                CurrentFile = path;
                return;
            }
            throw new IOException("Could not create a log file in " + LogDir);
        }

        private void CloseWriter()
        {
            try { if (writer != null) writer.Dispose(); } catch { }
            writer = null;
        }

        public void Dispose()
        {
            lock (gate) { CloseWriter(); }
        }

        /// <summary>Reads this computer's saved samples between two times, oldest first.</summary>
        public List<Sample> Read(DateTime from, DateTime to, List<string> filesUsed)
        {
            List<Sample> all = new List<Sample>();
            string[] files;
            try { files = Directory.GetFiles(LogDir, "InternetLog_" + MachineTag + "_*.csv"); }
            catch { return all; }
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);

            foreach (string file in files)
            {
                try
                {
                    if (File.GetLastWriteTime(file) < from.AddMinutes(-5)) continue;
                    int before = all.Count;
                    ReadFile(file, from, to, all);
                    if (all.Count > before && filesUsed != null) filesUsed.Add(Path.GetFileName(file));
                }
                catch { }
            }
            all.Sort(delegate(Sample a, Sample b) { return a.Time.CompareTo(b.Time); });
            return all;
        }

        private const string TraceHeader = "Timestamp,Reason,Target,Reached,Hop,Address,Ms";

        public void AppendTrace(Trace t)
        {
            lock (gate)
            {
                try
                {
                    string path = Path.Combine(LogDir, "InternetTrace_" + MachineTag + "_" + t.Time.ToString("yyyy-MM-dd") + ".csv");
                    bool isNew = !File.Exists(path);
                    StringBuilder sb = new StringBuilder();
                    if (isNew) sb.AppendLine(TraceHeader);
                    string stamp = t.Time.ToString(TimeFormat, CultureInfo.InvariantCulture);
                    foreach (TraceHop h in t.Hops)
                        sb.Append(stamp).Append(',').Append(t.Reason).Append(',').Append(t.Target).Append(',').Append(t.Reached ? "1" : "0").Append(',')
                          .Append(h.Hop).Append(',').Append(h.Address).Append(',').Append(h.Ms >= 0 ? h.Ms.ToString() : "").AppendLine();
                    if (t.Hops.Count == 0)
                        sb.Append(stamp).Append(',').Append(t.Reason).Append(',').Append(t.Target).Append(",0,0,,").AppendLine();
                    File.AppendAllText(path, sb.ToString(), new UTF8Encoding(false));
                }
                catch { }
            }
        }

        public List<Trace> ReadTraces(DateTime from, DateTime to)
        {
            List<Trace> all = new List<Trace>();
            string[] files;
            try { files = Directory.GetFiles(LogDir, "InternetTrace_" + MachineTag + "_*.csv"); }
            catch { return all; }
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);
            foreach (string file in files)
            {
                try
                {
                    if (File.GetLastWriteTime(file) < from.AddMinutes(-5)) continue;
                    Trace cur = null;
                    foreach (string line in File.ReadAllLines(file))
                    {
                        string[] f = line.Split(',');
                        DateTime t;
                        if (f.Length < 7 || !DateTime.TryParseExact(f[0], TimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out t)) continue;
                        if (t < from || t > to) continue;
                        if (cur == null || cur.Time != t || cur.Reason != f[1])
                        {
                            cur = new Trace(); cur.Time = t; cur.Reason = f[1]; cur.Target = f[2]; cur.Reached = f[3] == "1";
                            all.Add(cur);
                        }
                        int hop, ms;
                        if (!int.TryParse(f[4], out hop) || hop <= 0) continue;
                        TraceHop h = new TraceHop(); h.Hop = hop; h.Address = f[5];
                        if (int.TryParse(f[6], out ms)) h.Ms = ms;
                        cur.Hops.Add(h);
                    }
                }
                catch { }
            }
            return all;
        }

        private static readonly Regex ResultColumn = new Regex("^(HTTP|TCP|GW|DNS|PROXY)_(.+)_Result$");

        internal static void ReadFile(string file, DateTime from, DateTime to, List<Sample> into)
        {
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (StreamReader sr = new StreamReader(fs))
            {
                string headerLine = sr.ReadLine();
                if (headerLine == null) return;
                string[] cols = headerLine.Split(',');
                int iStatus = Array.IndexOf(cols, "Status");
                int iInterval = Array.IndexOf(cols, "IntervalMs");
                int iLocal = Array.IndexOf(cols, "LocalIP");
                int iExt = Array.IndexOf(cols, "ExternalIP");
                int iSsid = Array.IndexOf(cols, "WiFi_SSID"), iBssid = Array.IndexOf(cols, "WiFi_BSSID"), iSignal = Array.IndexOf(cols, "WiFi_Signal");
                int iLink = Array.IndexOf(cols, "WiFi_LinkMbps");
                if (cols.Length < 3 || cols[0] != "Timestamp" || iStatus < 0) return;

                List<CheckDef> defs = new List<CheckDef>();
                List<int> resultIdx = new List<int>();
                for (int i = 0; i < cols.Length - 1; i++)
                {
                    Match m = ResultColumn.Match(cols[i]);
                    if (!m.Success) continue;
                    defs.Add(new CheckDef(m.Groups[1].Value, m.Groups[2].Value, ""));
                    resultIdx.Add(i);
                }
                Schema schema = new Schema();
                schema.Defs = defs.ToArray();

                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    string[] f = line.Split(',');
                    if (f.Length < cols.Length) continue;   // partly written last line
                    DateTime t;
                    if (!DateTime.TryParseExact(f[0], TimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out t)) continue;
                    if (t < from || t > to) continue;

                    Sample s = new Sample();
                    s.Time = t;
                    s.Status = string.Intern(f[iStatus]);
                    int iv;
                    s.IntervalMs = (iInterval >= 0 && int.TryParse(f[iInterval], out iv)) ? iv : 1000;
                    s.Schema = schema;
                    s.LocalIP = iLocal >= 0 ? string.Intern(f[iLocal]) : "";
                    s.ExternalIP = iExt >= 0 ? string.Intern(f[iExt]) : "";
                    if (iSsid >= 0) s.WifiSsid = string.Intern(f[iSsid]);
                    if (iBssid >= 0) s.WifiBssid = string.Intern(f[iBssid]);
                    int sig;
                    if (iSignal >= 0 && int.TryParse(f[iSignal], out sig)) s.WifiSignal = sig;
                    if (iLink >= 0 && int.TryParse(f[iLink], out sig)) s.WifiLinkMbps = sig;
                    s.R = new CheckResult[defs.Count];
                    for (int c = 0; c < defs.Count; c++)
                    {
                        string res = f[resultIdx[c]];
                        if (res.Length == 0) continue;
                        CheckResult r = new CheckResult();
                        r.Tested = true;
                        r.Ok = res == "OK";
                        r.Detail = string.Intern(res);
                        int ms;
                        if (int.TryParse(f[resultIdx[c] + 1], out ms)) r.Ms = ms;
                        s.R[c] = r;
                    }
                    into.Add(s);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Running totals shown in the window while monitoring
    // ------------------------------------------------------------------
    internal sealed class SessionStats
    {
        public DateTime Started;
        public int Samples;
        public double MonitoredSec;
        public double DownSec;
        public double DegradedSec;
        public int Outages;
        public double CurrentOutageSec;
        public double LongestOutageSec;
        public int LastResponseMs = -1;
        public long ResponseSum;
        public int ResponseCount;
        // The newest sample has no successor yet; it stands for its own interval (as in the report).
        public double TailSec;
        public int TailSeverity;

        public double TotalSec { get { return MonitoredSec + TailSec; } }
        public double TotalDownSec { get { return DownSec + (TailSeverity == 2 ? TailSec : 0); } }

        public double AvailabilityPct
        {
            get { return TotalSec <= 0 ? 100.0 : 100.0 * (TotalSec - TotalDownSec) / TotalSec; }
        }
    }

    // ------------------------------------------------------------------
    // The engine: one background thread taking a sample every interval
    // ------------------------------------------------------------------
    internal sealed class Engine
    {
        public const int AdaptiveSlowMs = 5000;
        public const int AdaptiveFastMs = 1000;

        public readonly Settings Settings;
        public readonly LogStore Store;
        public readonly Schema Schema;
        public readonly int IntervalMs;          // 0 = adaptive
        public readonly int DurationMinutes;     // 0 = until stopped
        public readonly bool KeepAwake;

        public event Action<Sample> SampleTaken;
        public event Action<bool> Stopped;       // true = the chosen run time elapsed

        public volatile NetInfo Net = new NetInfo();
        public volatile ProxyInfo Proxy = new ProxyInfo();
        public volatile bool DirectBlockedByPolicy;
        public volatile string LastExternalIP = "";
        public readonly HashSet<string> ServedFrom = new HashSet<string>();
        public volatile WifiInfo LastWifi;
        public readonly List<Trace> Traces = new List<Trace>();
        private DateTime lastTrace = DateTime.MinValue;
        private bool baselineTraced;
        private const int MaxTraces = 60;
        private DateTime[] httpLastTested;
        private DateTime[] httpPausedUntil;
        public const int RateLimitPauseMinutes = 15;
        public readonly SessionStats Stats = new SessionStats();
        public readonly Dictionary<string, string> CertIssuers = new Dictionary<string, string>();

        private readonly List<Sample> samples = new List<Sample>();
        private readonly ManualResetEvent stopEvent = new ManualResetEvent(false);
        private Thread thread;

        private readonly int httpCount, tcpCount, iGw, iDns, iProxy;
        private readonly bool[] httpEverOk;
        private bool gatewayEverOk, directEverOk;
        private int healthySamples;      // samples in which at least one web check worked
        private int fastLeft;
        private Sample previous;
        private DateTime lastNetRefresh = DateTime.MinValue;
        private DateTime lastProxyRefresh = DateTime.MinValue;
        private readonly string dnsTestName;

        public Engine(Settings settings, LogStore store, int intervalMs, int durationMinutes, bool keepAwake)
        {
            Settings = settings;
            Store = store;
            IntervalMs = intervalMs;
            DurationMinutes = durationMinutes;
            KeepAwake = keepAwake;

            List<CheckDef> defs = new List<CheckDef>();
            foreach (HttpTarget h in settings.Http) { CheckDef d = new CheckDef("HTTP", h.Name, h.Url); d.Region = h.Region; d.Service = h.Service; defs.Add(d); }
            foreach (TcpTarget t in settings.Tcp) { CheckDef d = new CheckDef("TCP", t.Name, t.Host + ":" + t.Port); d.Region = t.Region; defs.Add(d); }
            httpCount = settings.Http.Count;
            tcpCount = settings.Tcp.Count;
            iGw = defs.Count; defs.Add(new CheckDef("GW", "Gateway", "Default gateway (ping)"));
            iDns = defs.Count; defs.Add(new CheckDef("DNS", "Lookup", "DNS server (UDP query)"));
            iProxy = defs.Count; defs.Add(new CheckDef("PROXY", "Proxy", "Configured proxy (TCP)"));
            for (int i = iGw; i <= iProxy; i++) defs[i].Region = "On site";
            Schema = new Schema();
            Schema.Defs = defs.ToArray();
            httpEverOk = new bool[httpCount];
            httpLastTested = new DateTime[httpCount];
            httpPausedUntil = new DateTime[httpCount];

            string host = "www.google.com";
            try { host = new Uri(settings.Http[0].Url).Host; } catch { }
            IPAddress literal;
            dnsTestName = IPAddress.TryParse(host, out literal) ? "www.google.com" : host;
        }

        public bool IsRunning { get { return thread != null && thread.IsAlive; } }

        public void Start()
        {
            Stats.Started = DateTime.Now;
            thread = new Thread(Loop);
            thread.IsBackground = true;
            thread.Name = "InternetMonitor.Engine";
            thread.Start();
        }

        public void Stop()
        {
            stopEvent.Set();
        }

        public bool WaitForExit(int ms)
        {
            return thread == null || thread.Join(ms);
        }

        public List<Sample> Snapshot()
        {
            lock (samples) { return new List<Sample>(samples); }
        }

        public bool IsHttpExcluded(int index)
        {
            return healthySamples >= 5 && !httpEverOk[index] && !Settings.Http[index].Service;
        }

        /// <summary>True while a site that answered "429 Too Many Requests" is being left alone.</summary>
        public bool IsHttpPaused(int index)
        {
            return DateTime.Now < httpPausedUntil[index];
        }

        public List<Trace> TraceSnapshot()
        {
            lock (Traces) { return new List<Trace>(Traces); }
        }

        // Runs on its own thread so that sampling never waits for it.
        private void StartTrace(string reason)
        {
            lock (Traces) { if (Traces.Count >= MaxTraces) return; }
            lastTrace = DateTime.Now;
            Task.Factory.StartNew(delegate
            {
                Trace t = TraceRoute.Run(TraceRoute.DefaultTarget, reason, 1200);
                lock (Traces) { Traces.Add(t); }
                Store.AppendTrace(t);
            }, TaskCreationOptions.LongRunning);
        }

        [DllImport("kernel32.dll")]
        private static extern uint SetThreadExecutionState(uint flags);
        private const uint ES_CONTINUOUS = 0x80000000, ES_SYSTEM_REQUIRED = 0x00000001;

        private void Loop()
        {
            bool timedOut = false;
            try
            {
                if (KeepAwake) SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
                DateTime end = DurationMinutes > 0 ? DateTime.Now.AddMinutes(DurationMinutes) : DateTime.MaxValue;

                while (!stopEvent.WaitOne(0))
                {
                    if (DateTime.Now >= end) { timedOut = true; break; }
                    Stopwatch sw = Stopwatch.StartNew();

                    Sample s = TakeSample();
                    s.IntervalMs = NextInterval(s.Status);

                    // Route traces: one while healthy for comparison, then one the moment each outage begins.
                    int sevNow = St.Severity(s.Status), sevBefore = previous == null ? 0 : St.Severity(previous.Status);
                    if (!baselineTraced && sevNow == 0) { baselineTraced = true; StartTrace("BASELINE"); }
                    else if (sevNow == 2 && sevBefore != 2 && (DateTime.Now - lastTrace).TotalSeconds >= 20) StartTrace("OUTAGE");

                    UpdateStats(s);
                    lock (samples) { samples.Add(s); }
                    Store.Append(s);

                    Action<Sample> h = SampleTaken;
                    if (h != null) { try { h(s); } catch { } }

                    int wait = (int)Math.Max(0, s.IntervalMs - sw.ElapsedMilliseconds);
                    if (stopEvent.WaitOne(wait)) break;
                }
            }
            finally
            {
                if (KeepAwake) SetThreadExecutionState(ES_CONTINUOUS);
                Action<bool> h = Stopped;
                if (h != null) { try { h(timedOut); } catch { } }
            }
        }

        private int NextInterval(string status)
        {
            if (IntervalMs > 0) return IntervalMs;
            // Adaptive: relaxed while healthy, once a second during and just after any problem
            // so that the start and end of an outage are timed to the second.
            if (status != St.Online) fastLeft = 5;
            else if (fastLeft > 0) fastLeft--;
            return fastLeft > 0 ? AdaptiveFastMs : AdaptiveSlowMs;
        }

        private void UpdateStats(Sample s)
        {
            SessionStats st = Stats;
            lock (st)
            {
                st.Samples++;
                if (previous != null)
                {
                    double dt = Math.Min((s.Time - previous.Time).TotalSeconds, Weights.CapSeconds(previous.IntervalMs));
                    if (dt < 0) dt = 0;
                    st.MonitoredSec += dt;
                    int prevSev = St.Severity(previous.Status);
                    if (prevSev == 2)
                    {
                        st.DownSec += dt;
                        st.CurrentOutageSec += dt;
                        if (st.CurrentOutageSec > st.LongestOutageSec) st.LongestOutageSec = st.CurrentOutageSec;
                    }
                    else if (prevSev == 1) st.DegradedSec += dt;
                }
                int sev = St.Severity(s.Status);
                int before = previous == null ? 0 : St.Severity(previous.Status);
                if (sev == 2 && before != 2) { st.Outages++; st.CurrentOutageSec = 0; }
                st.TailSec = s.IntervalMs / 1000.0;
                st.TailSeverity = sev;

                long sum = 0; int n = 0;
                for (int i = 0; i < httpCount; i++)
                {
                    if (s.R[i].Tested && s.R[i].Ok && !Settings.Http[i].Service) { sum += s.R[i].Ms; n++; }
                }
                st.LastResponseMs = n > 0 ? (int)(sum / n) : -1;
                if (n > 0) { st.ResponseSum += sum / n; st.ResponseCount++; }
            }
            previous = s;
        }

        private Sample TakeSample()
        {
            DateTime now = DateTime.Now;

            // Adapter details are cheap but not free; proxy auto-detection can be slow.
            if ((now - lastNetRefresh).TotalSeconds >= 10 || !Net.LinkUp)
            {
                Net = NetInfo.Detect();
                lastNetRefresh = now;
            }
            if ((now - lastProxyRefresh).TotalSeconds >= 60)
            {
                Proxy = ProxyInfo.Detect(Settings.Http[0].Url);
                lastProxyRefresh = now;
            }
            NetInfo net = Net;
            ProxyInfo proxy = Proxy;
            int timeout = Settings.TimeoutMs;
            int shortTimeout = Math.Min(timeout, 1500);

            int total = Schema.Defs.Length;
            Task<CheckResult>[] tasks = new Task<CheckResult>[total];
            HttpProbe[] httpProbes = new HttpProbe[httpCount];

            for (int i = 0; i < httpCount; i++)
            {
                HttpTarget target = Settings.Http[i];
                if (now < httpPausedUntil[i]) continue;
                if (target.EverySec > 0 && (now - httpLastTested[i]).TotalSeconds < target.EverySec - 0.5) continue;
                httpLastTested[i] = now;
                HttpProbe p = new HttpProbe(target, timeout);
                httpProbes[i] = p;
                tasks[i] = Task.Factory.StartNew<CheckResult>(p.Run, TaskCreationOptions.LongRunning);
            }
            for (int i = 0; i < tcpCount; i++)
            {
                TcpTarget t = Settings.Tcp[i];
                tasks[httpCount + i] = Task.Factory.StartNew<CheckResult>(delegate { return Probes.Tcp(t.Host, t.Port, timeout); }, TaskCreationOptions.LongRunning);
            }
            if (net.Gateway != null)
                tasks[iGw] = Task.Factory.StartNew<CheckResult>(delegate { return Probes.PingHost(net.Gateway, 1000); }, TaskCreationOptions.LongRunning);
            if (net.DnsServers.Count > 0)
                tasks[iDns] = Task.Factory.StartNew<CheckResult>(delegate { return Probes.Dns(net.DnsServers, dnsTestName, shortTimeout); }, TaskCreationOptions.LongRunning);
            if (proxy.Explicit)
                tasks[iProxy] = Task.Factory.StartNew<CheckResult>(delegate { return Probes.Tcp(proxy.Host, proxy.Port, shortTimeout); }, TaskCreationOptions.LongRunning);

            List<Task> running = new List<Task>();
            foreach (Task<CheckResult> t in tasks) { if (t != null) running.Add(t); }
            try { Task.WaitAll(running.ToArray(), timeout + 1500); } catch { }

            Sample s = new Sample();
            s.Time = now;
            s.Schema = Schema;
            s.R = new CheckResult[total];
            for (int i = 0; i < total; i++)
            {
                if (tasks[i] == null) continue;
                if (tasks[i].Status == TaskStatus.RanToCompletion) s.R[i] = tasks[i].Result;
                else
                {
                    // Hard deadline passed (e.g. a DNS lookup that ignores the request timeout).
                    s.R[i] = CheckResult.Fail("TIMEOUT", timeout + 1500);
                    if (i < httpCount) httpProbes[i].Abort();
                }
                // A site that says "too many requests" is left completely alone for a while.
                if (i < httpCount && s.R[i].Detail == "RATE_LIMITED") httpPausedUntil[i] = now.AddMinutes(RateLimitPauseMinutes);
            }

            // Facts picked up along the way.
            for (int i = 0; i < httpCount; i++)
            {
                if (!s.R[i].Ok) continue;
                httpEverOk[i] = true;
                if (httpProbes[i].ExternalIP != null) LastExternalIP = httpProbes[i].ExternalIP;
                if (httpProbes[i].ServedFrom != null) { lock (ServedFrom) { ServedFrom.Add(httpProbes[i].ServedFrom); } }
                if (httpProbes[i].CertIssuer != null)
                {
                    lock (CertIssuers) { CertIssuers[Settings.Http[i].Name] = httpProbes[i].CertIssuer; }
                }
            }
            bool anyTcpOk = false;
            for (int i = 0; i < tcpCount; i++) { if (s.R[httpCount + i].Ok) anyTcpOk = true; }
            if (anyTcpOk) directEverOk = true;
            if (s.R[iGw].Ok) gatewayEverOk = true;

            bool anyHttpOk = false;
            for (int i = 0; i < httpCount; i++) { if (s.R[i].Ok) anyHttpOk = true; }
            if (anyHttpOk) healthySamples++;

            // Work out the conclusion. A web check that has never once succeeded while the
            // others are fine is assumed to be blocked by filtering policy and is ignored.
            int counted = 0, ok = 0;
            for (int i = 0; i < httpCount; i++)
            {
                if (IsHttpExcluded(i) || Settings.Http[i].Service || !s.R[i].Tested) continue;
                counted++;
                if (s.R[i].Ok) ok++;
            }
            // Nothing countable this round (every site paused): fall back on the direct connections.
            if (counted == 0 && anyTcpOk) { counted = 1; ok = 1; }
            DirectBlockedByPolicy = tcpCount > 0 && !directEverOk && healthySamples >= 5;

            Tri gw = !s.R[iGw].Tested || !gatewayEverOk ? Tri.NA : (s.R[iGw].Ok ? Tri.Ok : Tri.Fail);
            Tri dns = !s.R[iDns].Tested ? Tri.NA : (s.R[iDns].Ok ? Tri.Ok : Tri.Fail);
            Tri px = !s.R[iProxy].Tested ? Tri.NA : (s.R[iProxy].Ok ? Tri.Ok : Tri.Fail);
            Tri direct = tcpCount == 0 ? Tri.NA : anyTcpOk ? Tri.Ok : (directEverOk ? Tri.Fail : Tri.NA);

            s.Status = Diagnosis.Classify(net.LinkUp, ok, counted, gw, dns, px, direct, proxy.Explicit);
            s.LocalIP = net.LocalIP;
            s.ExternalIP = LastExternalIP;
            if (net.AdapterType == "Wi-Fi")
            {
                // Link speed changes from moment to moment, so read it fresh rather than from the 10-second cache.
                NetInfo fresh = (now - lastNetRefresh).TotalSeconds < 1 ? net : NetInfo.Detect();
                s.WifiLinkMbps = fresh.AdapterType == "Wi-Fi" ? fresh.LinkMbps : -1;
                WifiInfo wifi = Wifi.Query();
                LastWifi = wifi;
                if (wifi != null) { s.WifiSsid = wifi.Ssid; s.WifiBssid = wifi.Bssid; s.WifiSignal = wifi.Signal; }
            }
            else LastWifi = null;
            return s;
        }
    }
}
