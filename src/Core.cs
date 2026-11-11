// Internet Monitor - core model, settings, network discovery and probes.
// Written in C# 5 on purpose: it compiles with the csc.exe that ships inside
// every copy of Windows (.NET Framework 4.x), so no Visual Studio is needed.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Cache;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace InternetMonitor
{
    internal static class AppInfo
    {
        public const string Name = "Internet Monitor";
        public const string Version = "2.4.0";
    }

    // ------------------------------------------------------------------
    // Status codes (what a single sample concluded)
    // ------------------------------------------------------------------
    internal static class St
    {
        public const string Online = "ONLINE";
        public const string Degraded = "DEGRADED";
        public const string Inspection = "INSPECTION_FAULT";
        public const string Proxy = "PROXY_FAULT";
        public const string InternetDown = "INTERNET_DOWN";
        public const string WebDown = "WEB_DOWN";
        public const string Dns = "DNS_FAILURE";
        public const string LocalNetwork = "LOCAL_NETWORK";
        public const string NoNetwork = "NO_NETWORK";

        public static readonly string[] All = { Online, Degraded, Inspection, Proxy, InternetDown, WebDown, Dns, LocalNetwork, NoNetwork };

        /// <summary>0 = fine, 1 = degraded (still usable), 2 = outage.</summary>
        public static int Severity(string code)
        {
            if (code == Online) return 0;
            if (code == Degraded) return 1;
            return 2;
        }

        public static string Label(string code)
        {
            switch (code)
            {
                case Online: return "Online";
                case Degraded: return "Degraded";
                case Inspection: return "HTTPS inspection fault";
                case Proxy: return "Web filter / proxy fault";
                case InternetDown: return "Internet outage";
                case WebDown: return "Web access down";
                case Dns: return "DNS failure";
                case LocalNetwork: return "Local network fault";
                case NoNetwork: return "Not connected";
                default: return code;
            }
        }

        public static string Explain(string code)
        {
            switch (code)
            {
                case Online:
                    return "All web checks are succeeding.";
                case Degraded:
                    return "Some web checks are failing while others succeed. Browsing mostly works but may be slow or patchy.";
                case Inspection:
                    return "Secure (HTTPS) websites that the web filter decrypts are failing, while websites it does not decrypt, and the connection underneath, are still working. That points at the filter's HTTPS inspection rather than the internet line.";
                case Proxy:
                    return "Web requests are failing, but this computer can still reach the internet directly. That points at the web filter / proxy rather than the internet line.";
                case InternetDown:
                    return "Web requests and direct connections to the internet are both failing, while the local network is still up. That points at the internet line, firewall or ISP.";
                case WebDown:
                    return "All web requests are failing. Direct connections are not permitted from this network, so the fault cannot be narrowed down further than the proxy or the internet line.";
                case Dns:
                    return "Names cannot be resolved by the DNS server, although the internet itself is reachable. That points at the DNS service.";
                case LocalNetwork:
                    return "This computer cannot reach its own default gateway. That points at Wi-Fi, cabling or a switch near this computer, not the internet line.";
                case NoNetwork:
                    return "This computer has no active network connection (Wi-Fi disconnected or cable unplugged).";
                default:
                    return "";
            }
        }
    }

    // ------------------------------------------------------------------
    // Data model
    // ------------------------------------------------------------------
    internal sealed class CheckDef
    {
        public string Kind;    // HTTP, TCP, GW, DNS, PROXY
        public string Name;
        public string Target;
        public string Region = "";   // where the far end is run from, e.g. "UK"
        public bool Service;         // reported on its own; does not decide Online / Outage

        public CheckDef(string kind, string name, string target)
        {
            Kind = kind; Name = name; Target = target;
        }

        public string Key { get { return Kind + "_" + Name; } }

        public string KindLabel
        {
            get
            {
                switch (Kind)
                {
                    case "HTTP": return "Web request";
                    case "TCP": return "Direct connection";
                    case "GW": return "Local network";
                    case "DNS": return "DNS";
                    case "PROXY": return "Proxy";
                    default: return Kind;
                }
            }
        }
    }

    internal struct CheckResult
    {
        public bool Tested;
        public bool Ok;
        public int Ms;
        public string Detail;
        // Web checks only: how long each stage took (-1 = not reached, or not measured).
        public int DnsMs, TcpMs, TlsMs;

        public static CheckResult Pass(long ms)
        {
            CheckResult r = new CheckResult();
            r.Tested = true; r.Ok = true; r.Ms = (int)ms; r.Detail = "OK"; r.DnsMs = r.TcpMs = r.TlsMs = -1;
            return r;
        }

        public static CheckResult Fail(string detail, long ms)
        {
            CheckResult r = new CheckResult();
            r.Tested = true; r.Ok = false; r.Ms = (int)ms; r.Detail = detail; r.DnsMs = r.TcpMs = r.TlsMs = -1;
            return r;
        }
    }

    internal sealed class Schema
    {
        public CheckDef[] Defs;
    }

    internal sealed class Sample
    {
        public DateTime Time;
        public string Status;
        public int IntervalMs;
        public Schema Schema;
        public CheckResult[] R;
        public string LocalIP;
        public string ExternalIP;
        public string Adapter = "";     // name of the network adapter the checks went out through
        public string Inspected = "";   // names of the web checks whose HTTPS is being decrypted, separated by |
        public string WifiSsid = "";
        public string WifiBssid = "";
        public int WifiSignal = -1;
        public int WifiLinkMbps = -1;   // negotiated link speed: needs no permission, falls as signal worsens
    }

    internal static class Weights
    {
        /// <summary>
        /// Longest stretch of time one sample is allowed to stand for. If the next
        /// sample arrives later than this (PC asleep, app closed) the remainder is
        /// treated as "no data" rather than being counted as up or down.
        /// </summary>
        public static double CapSeconds(int intervalMs)
        {
            if (intervalMs <= 0) intervalMs = 1000;
            return (intervalMs * 2 + 10000) / 1000.0;
        }
    }

    // ------------------------------------------------------------------
    // Settings (optional InternetMonitor.ini next to the EXE)
    // ------------------------------------------------------------------
    internal sealed class HttpTarget
    {
        public string Name;
        public string Url;
        public int ExpectStatus;     // 0 = any 2xx
        public string ExpectText;    // null = don't check body
        public string Region = "";
        public int EverySec;         // 0 = every sample. Above 0 = a gentle "service check" at most this often.
        public bool Service;         // true = reported separately, never counted towards Online / Outage
    }

    internal sealed class TcpTarget
    {
        public string Name;
        public string Host;
        public int Port;
        public string Region = "";
    }

    internal sealed class Settings
    {
        public string Organisation = "";
        public string Contact = "";
        public string WifiDetails = "auto";
        public string DataFolder = "";
        public string Adapter = "";     // adapter name or its IP address; empty = let Windows choose
        public int TimeoutMs = 3000;
        public string DefaultInterval = "adaptive";
        public int DefaultDurationMinutes = 0;
        public bool KeepAwake = true;
        public List<HttpTarget> Http = new List<HttpTarget>();
        public List<TcpTarget> Tcp = new List<TcpTarget>();
        public string LoadedFrom = "";
        public List<string> Warnings = new List<string>();

        public static string SafeName(string s)
        {
            string n = Regex.Replace(s ?? "", "[^A-Za-z0-9]", "");
            return n.Length == 0 ? "Target" : n;
        }

        public static Settings Load(string exeDir)
        {
            Settings s = new Settings();
            string path = Path.Combine(exeDir, "InternetMonitor.ini");
            List<HttpTarget> http = new List<HttpTarget>();
            List<TcpTarget> tcp = new List<TcpTarget>();

            if (File.Exists(path))
            {
                try
                {
                    foreach (string raw in File.ReadAllLines(path))
                    {
                        string line = raw.Trim();
                        if (line.Length == 0 || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;
                        int eq = line.IndexOf('=');
                        if (eq <= 0) continue;
                        string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                        string val = line.Substring(eq + 1).Trim();
                        int n;
                        switch (key)
                        {
                            case "organisation":
                            case "organization":
                                s.Organisation = val; break;
                            case "wifidetails":
                                val = val.ToLowerInvariant();
                                if (val == "on" || val == "off" || val == "auto") s.WifiDetails = val;
                                break;
                            case "contact":
                                s.Contact = Regex.Replace(val, @"[^A-Za-z0-9 @._:/+-]", "").Trim(); break;
                            case "datafolder":
                                s.DataFolder = Environment.ExpandEnvironmentVariables(val); break;
                            case "adapter":
                                s.Adapter = val.Equals("auto", StringComparison.OrdinalIgnoreCase) || val.Equals("automatic", StringComparison.OrdinalIgnoreCase) ? "" : val;
                                break;
                            case "timeoutms":
                                if (int.TryParse(val, out n)) s.TimeoutMs = Math.Max(500, Math.Min(30000, n));
                                break;
                            case "interval":
                                s.DefaultInterval = val.ToLowerInvariant(); break;
                            case "durationminutes":
                                if (int.TryParse(val, out n)) s.DefaultDurationMinutes = Math.Max(0, n);
                                break;
                            case "keepawake":
                                s.KeepAwake = IsTrue(val); break;
                            case "http":
                                HttpTarget h = ParseHttp(val);
                                if (h != null) http.Add(h); else s.Warnings.Add("Ignored Http line: " + val);
                                break;
                            case "tcp":
                                TcpTarget t = ParseTcp(val);
                                if (t != null) tcp.Add(t); else s.Warnings.Add("Ignored Tcp line: " + val);
                                break;
                        }
                    }
                    s.LoadedFrom = path;
                }
                catch (Exception ex)
                {
                    s.Warnings.Add("Could not read InternetMonitor.ini: " + ex.Message);
                }
            }

            if (http.Count == 0)
            {
                // Global networks: US-run, but answered by whichever of their sites is nearest (London, from Wales).
                http.Add(MakeHttp("Google", "https://www.google.com/generate_204", 204, null, Global));
                http.Add(MakeHttp("Microsoft", "http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test", Global));
                http.Add(MakeHttp("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace", 200, "colo=", Global));
                // Android's own connectivity test address. Web filters that decrypt HTTPS normally leave it alone,
                // which makes it the comparison that shows whether a fault is in the filter's HTTPS inspection.
                http.Add(MakeHttp("Gstatic", "https://connectivitycheck.gstatic.com/generate_204", 204, null, Global));
                // Hwb is an ordinary website, not a connectivity-test endpoint, so it is only asked
                // once a minute and is reported as a service in its own right.
                HttpTarget hwb = MakeHttp("Hwb", "https://hwb.gov.wales/robots.txt", 200, "User-agent", "Wales");
                hwb.EverySec = 60; hwb.Service = true;
                http.Add(hwb);
            }
            if (tcp.Count == 0 && !s.TcpDisabled)
            {
                tcp.Add(MakeTcp("Cloudflare", "1.1.1.1", 443, Global));
                tcp.Add(MakeTcp("Google", "8.8.8.8", 443, Global));
                tcp.Add(MakeTcp("Quad9", "9.9.9.9", 443, "Global (Swiss)"));
            }
            s.Http = Dedupe(http);
            s.Tcp = DedupeTcp(tcp);
            return s;
        }

        public bool TcpDisabled = false;

        private static bool IsTrue(string v)
        {
            v = v.ToLowerInvariant();
            return v == "1" || v == "true" || v == "yes" || v == "on";
        }

        public const string Global = "Global (US-run)";

        private static HttpTarget MakeHttp(string name, string url, int status, string text, string region)
        {
            HttpTarget h = new HttpTarget();
            h.Name = name; h.Url = url; h.ExpectStatus = status; h.ExpectText = text; h.Region = region;
            return h;
        }

        private static TcpTarget MakeTcp(string name, string host, int port, string region)
        {
            TcpTarget t = new TcpTarget();
            t.Name = name; t.Host = host; t.Port = port; t.Region = region;
            return t;
        }

        private static string CleanRegion(string s)
        {
            s = Regex.Replace(s ?? "", "[^A-Za-z0-9 ()/&.-]", "").Trim();
            return s.Length > 24 ? s.Substring(0, 24) : s;
        }

        // Http = Name | URL | status:204        or        Name | URL | text:some words
        private static HttpTarget ParseHttp(string val)
        {
            string[] p = val.Split('|');
            if (p.Length < 2) return null;
            Uri u;
            if (!Uri.TryCreate(p[1].Trim(), UriKind.Absolute, out u)) return null;
            if (u.Scheme != "http" && u.Scheme != "https") return null;
            HttpTarget h = MakeHttp(SafeName(p[0]), u.AbsoluteUri, 0, null, "");
            for (int i = 2; i < p.Length; i++)
            {
                string e = p[i].Trim();
                int n;
                if (e.StartsWith("status:", StringComparison.OrdinalIgnoreCase) && int.TryParse(e.Substring(7), out n)) h.ExpectStatus = n;
                else if (e.StartsWith("text:", StringComparison.OrdinalIgnoreCase)) h.ExpectText = e.Substring(5);
                else if (e.StartsWith("region:", StringComparison.OrdinalIgnoreCase)) h.Region = CleanRegion(e.Substring(7));
                else if (e.StartsWith("every:", StringComparison.OrdinalIgnoreCase) && int.TryParse(e.Substring(6), out n))
                {
                    h.EverySec = Math.Max(10, Math.Min(3600, n));
                    h.Service = true;
                }
                else if (e.Equals("service", StringComparison.OrdinalIgnoreCase)) h.Service = true;
            }
            return h;
        }

        // Tcp = Name | host-or-ip | port | region:UK
        private static TcpTarget ParseTcp(string val)
        {
            string[] p = val.Split('|');
            int port;
            if (p.Length < 3 || !int.TryParse(p[2].Trim(), out port) || port < 1 || port > 65535) return null;
            if (p[1].Trim().Length == 0) return null;
            string region = "";
            for (int i = 3; i < p.Length; i++)
            {
                string e = p[i].Trim();
                if (e.StartsWith("region:", StringComparison.OrdinalIgnoreCase)) region = CleanRegion(e.Substring(7));
            }
            return MakeTcp(SafeName(p[0]), p[1].Trim(), port, region);
        }

        private static List<HttpTarget> Dedupe(List<HttpTarget> list)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<HttpTarget> r = new List<HttpTarget>();
            foreach (HttpTarget h in list) { h.Name = SafeName(h.Name); if (seen.Add(h.Name) && r.Count < 8) r.Add(h); }
            return r;
        }

        private static List<TcpTarget> DedupeTcp(List<TcpTarget> list)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            List<TcpTarget> r = new List<TcpTarget>();
            foreach (TcpTarget t in list) { t.Name = SafeName(t.Name); if (seen.Add(t.Name) && r.Count < 8) r.Add(t); }
            return r;
        }
    }

    // ------------------------------------------------------------------
    // Local network discovery (adapter, gateway, DNS servers, proxy)
    // ------------------------------------------------------------------
    internal sealed class NetInfo
    {
        public bool LinkUp;
        public string Id = "";              // Windows' own identifier for the adapter; stays the same if it is renamed
        public string AdapterName = "";
        public string Description = "";
        public string AdapterType = "";
        public string LocalIP = "";
        public int LinkMbps = -1;
        public IPAddress Gateway;
        public List<IPAddress> DnsServers = new List<IPAddress>();
        private int score;

        private static readonly Regex Virtual = new Regex("Hyper-V|vEthernet|VMware|VirtualBox|WSL|Docker|Loopback|Bluetooth", RegexOptions.IgnoreCase);

        /// <summary>The adapter Windows would use by default.</summary>
        public static NetInfo Detect() { return Detect(""); }

        /// <summary>
        /// Details of one chosen adapter, or (with an empty id) of the one Windows would use.
        /// A chosen adapter that is unplugged or disabled comes back as "not connected".
        /// </summary>
        public static NetInfo Detect(string adapterId)
        {
            NetInfo best = null;
            foreach (NetInfo c in All())
            {
                if (!string.IsNullOrEmpty(adapterId))
                {
                    if (c.Id == adapterId) return c;
                    continue;
                }
                if (best == null || c.score > best.score) best = c;
            }
            return best ?? new NetInfo();
        }

        /// <summary>Finds an adapter by its name, description, IP address or id (for the settings file and command line).</summary>
        public static NetInfo Find(string text)
        {
            text = (text ?? "").Trim().Trim('"');
            if (text.Length == 0) return null;
            foreach (NetInfo c in All())
            {
                if (string.Equals(c.AdapterName, text, StringComparison.OrdinalIgnoreCase) || c.LocalIP == text
                    || string.Equals(c.Id, text, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(c.Description, text, StringComparison.OrdinalIgnoreCase)) return c;
            }
            return null;
        }

        /// <summary>Every connected adapter that has an IPv4 address.</summary>
        public static List<NetInfo> All()
        {
            List<NetInfo> all = new List<NetInfo>();
            string routeIp = RouteLocalIP();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback || ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    IPInterfaceProperties p = ni.GetIPProperties();
                    NetInfo c = new NetInfo();
                    c.Id = ni.Id;
                    c.AdapterName = ni.Name;
                    c.Description = ni.Description;
                    c.AdapterType = FriendlyType(ni.NetworkInterfaceType);
                    try { if (ni.Speed > 0) c.LinkMbps = (int)Math.Min(100000, ni.Speed / 1000000); } catch { }

                    foreach (UnicastIPAddressInformation ua in p.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        string ip = ua.Address.ToString();
                        if (ip.StartsWith("169.254.") || ip.StartsWith("127.")) continue;
                        if (c.LocalIP.Length == 0 || ip == routeIp) c.LocalIP = ip;
                    }
                    foreach (GatewayIPAddressInformation g in p.GatewayAddresses)
                    {
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))
                        {
                            c.Gateway = g.Address; break;
                        }
                    }
                    foreach (IPAddress d in p.DnsAddresses)
                    {
                        if (d.AddressFamily == AddressFamily.InterNetwork) c.DnsServers.Add(d);
                    }
                    foreach (IPAddress d in p.DnsAddresses)
                    {
                        // IPv6 resolvers after IPv4; skip the deprecated fec0:: placeholders Windows lists.
                        if (d.AddressFamily == AddressFamily.InterNetworkV6 && !d.IsIPv6SiteLocal) c.DnsServers.Add(d);
                    }

                    if (c.LocalIP.Length == 0) continue;
                    c.LinkUp = c.Gateway != null;

                    c.score = (c.Gateway != null ? 4 : 0) + (c.LocalIP == routeIp ? 2 : 0) + (Virtual.IsMatch(ni.Name + " " + ni.Description) ? 0 : 1);
                    all.Add(c);
                }
            }
            catch { }
            return all;
        }

        // Asks Windows which local address it would use to reach the internet.
        // A UDP "connect" sends nothing; it only selects a route.
        private static string RouteLocalIP()
        {
            try
            {
                using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.Connect("1.1.1.1", 53);
                    return ((IPEndPoint)s.LocalEndPoint).Address.ToString();
                }
            }
            catch { return ""; }
        }

        private static string FriendlyType(NetworkInterfaceType t)
        {
            switch (t)
            {
                case NetworkInterfaceType.Wireless80211: return "Wi-Fi";
                case NetworkInterfaceType.Ethernet:
                case NetworkInterfaceType.GigabitEthernet:
                case NetworkInterfaceType.FastEthernetT:
                case NetworkInterfaceType.FastEthernetFx:
                case NetworkInterfaceType.Ethernet3Megabit: return "Wired (Ethernet)";
                case NetworkInterfaceType.Ppp: return "PPP / VPN";
                default: return t.ToString();
            }
        }
    }

    internal sealed class ProxyInfo
    {
        public bool Explicit;
        public string Host = "";
        public int Port;
        public string Description = "None configured (direct, or a transparent filter)";

        public static ProxyInfo Detect(string sampleUrl)
        {
            ProxyInfo info = new ProxyInfo();
            try
            {
                IWebProxy p = WebRequest.DefaultWebProxy;
                Uri target = new Uri(sampleUrl);
                if (p == null || p.IsBypassed(target)) return info;
                Uri u = p.GetProxy(target);
                if (u == null || u == target || string.Equals(u.Host, target.Host, StringComparison.OrdinalIgnoreCase)) return info;
                info.Explicit = true;
                info.Host = u.Host;
                info.Port = u.Port;
                info.Description = u.Host + ":" + u.Port + " (from Windows proxy settings)";
            }
            catch { }
            return info;
        }
    }

    // ------------------------------------------------------------------
    // Probes. None of these throw; every outcome is a CheckResult.
    // ------------------------------------------------------------------
    /// <summary>
    /// What a website's certificate says about who is really answering. On a network that
    /// decrypts HTTPS, the filter replaces each site's certificate with one of its own.
    /// </summary>
    internal sealed class CertInfo
    {
        public string Issuer = "";          // full issuer name from the certificate
        public string IssuerShort = "";     // just the name (and organisation) for display
        public string Root = "";            // top of the chain Windows built
        public string Thumbprint = "";
        public bool Trusted;                // Windows accepted the certificate for this site
        public bool Inspected;              // not issued by a public authority: something is decrypting the traffic
        public string Why = "";

        private static readonly Regex FilterNames = new Regex(
            "intercept|inspection|decrypt|ssl.?proxy|https.?proxy|smoothwall|fortinet|fortigate|sophos|zscaler|netsweeper|lightspeed|securly|palo alto|"
            + "watchguard|sonicwall|barracuda|umbrella|forcepoint|iboss|squid|bluecoat|symantec web|mcafee web|checkpoint|check point|untangle|netskope|"
            + "kaspersky|eset|avast|bitdefender|content.?filter|web.?filter", RegexOptions.IgnoreCase);
        private static readonly Dictionary<string, bool> PublicRoots = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public static CertInfo From(X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            if (certificate == null) return null;
            CertInfo info = new CertInfo();
            try
            {
                X509Certificate2 cert = new X509Certificate2(certificate);
                info.Issuer = cert.Issuer;
                info.IssuerShort = ShortName(cert.Issuer);
                info.Thumbprint = cert.Thumbprint ?? "";
                info.Trusted = errors == SslPolicyErrors.None;

                X509Certificate2 root = null;
                if (chain != null && chain.ChainElements.Count > 0) root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                bool chainComplete = (errors & SslPolicyErrors.RemoteCertificateChainErrors) == 0 && root != null && root.Subject == root.Issuer;
                info.Root = chainComplete ? ShortName(root.Subject) : "";

                if (FilterNames.IsMatch(cert.Issuer))
                {
                    info.Inspected = true; info.Why = "its certificate was issued by a web filter";
                }
                else if (!chainComplete)
                {
                    info.Inspected = true; info.Why = "its certificate does not come from a public certificate authority, and this computer does not trust it";
                }
                else if (!IsPublicRoot(root))
                {
                    info.Inspected = true; info.Why = "its certificate comes from a privately installed authority, not a public one";
                }
            }
            catch { }
            return info;
        }

        /// <summary>For the case where only the certificate is to hand (requests made through a proxy).</summary>
        public static CertInfo From(X509Certificate certificate)
        {
            if (certificate == null) return null;
            try
            {
                using (X509Chain chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    bool ok = chain.Build(new X509Certificate2(certificate));
                    return From(certificate, chain, ok ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors);
                }
            }
            catch { return null; }
        }

        // Public authorities reach Windows through Microsoft's root programme, which files them under
        // "Third-Party Root Certification Authorities". A root that is trusted but not filed there was
        // installed by the organisation (Group Policy, device management or by hand).
        private static bool IsPublicRoot(X509Certificate2 root)
        {
            string thumb = root.Thumbprint ?? "";
            lock (PublicRoots)
            {
                bool known;
                if (PublicRoots.TryGetValue(thumb, out known)) return known;
            }
            bool found = root.Subject.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
            foreach (StoreLocation where in new StoreLocation[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
            {
                if (found) break;
                try
                {
                    X509Store store = new X509Store(StoreName.AuthRoot, where);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    try { found = store.Certificates.Find(X509FindType.FindByThumbprint, thumb, false).Count > 0; }
                    finally { store.Close(); }
                }
                catch { }
            }
            lock (PublicRoots) { PublicRoots[thumb] = found; }
            return found;
        }

        internal static string ShortName(string distinguishedName)
        {
            Match o = Regex.Match(distinguishedName, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
            Match cn = Regex.Match(distinguishedName, @"(?:^|,\s*)CN=(""[^""]+""|[^,]+)");
            string name = cn.Success ? cn.Groups[1].Value.Trim('"') : distinguishedName;
            if (o.Success && o.Groups[1].Value.Trim('"') != name) name += " (" + o.Groups[1].Value.Trim('"') + ")";
            return name;
        }
    }

    /// <summary>
    /// One web request, timed in stages: name lookup, connecting, secure handshake, reply.
    /// Knowing the stage is what separates "the line is down" (cannot connect) from
    /// "the filter's HTTPS inspection has stalled" (connects at once, handshake never completes).
    /// </summary>
    internal sealed class HttpProbe
    {
        private readonly HttpTarget target;
        private readonly int timeoutMs;
        private readonly IPAddress bindTo;      // local address of the chosen adapter; null = let Windows choose
        private readonly bool viaProxy;         // an explicit proxy is configured: let .NET handle it (no stage timings)
        private volatile HttpWebRequest request;
        private volatile Socket socket;
        private volatile string stage = "DNS";
        private volatile bool aborted;

        public static string UserAgent = "InternetMonitor/" + AppInfo.Version;

        public string ExternalIP;
        public string ServedFrom;    // Cloudflare's own name for the site that answered, e.g. LHR
        public CertInfo Cert;        // null for plain HTTP, or when the handshake never got as far as a certificate
        public string CertIssuer { get { return Cert != null ? Cert.Issuer : null; } }

        public HttpProbe(HttpTarget target, int timeoutMs, IPAddress bindTo, bool viaProxy)
        {
            this.target = target;
            this.timeoutMs = timeoutMs;
            this.bindTo = bindTo;
            this.viaProxy = viaProxy;
        }

        /// <summary>The failure to record when the hard deadline passes: names the stage that was in progress.</summary>
        public string StageTimeout { get { return viaProxy ? "TIMEOUT" : stage + "_TIMEOUT"; } }

        public void Abort()
        {
            aborted = true;
            try { HttpWebRequest r = request; if (r != null) r.Abort(); } catch { }
            try { Socket s = socket; if (s != null) s.Close(); } catch { }
        }

        public CheckResult Run()
        {
            return viaProxy ? RunViaProxy() : RunStaged();
        }

        // ---------------------------------------------------------------- direct, stage by stage
        private CheckResult RunStaged()
        {
            Stopwatch sw = Stopwatch.StartNew();
            int dnsMs = -1, tcpMs = -1, tlsMs = -1;
            Socket s = null;
            Stream stream = null;
            try
            {
                Uri uri = new Uri(target.Url);
                bool https = uri.Scheme == "https";

                // 1. name lookup (by Windows, exactly as a browser's would be)
                stage = "DNS";
                IPAddress literal;
                IPAddress[] found = IPAddress.TryParse(uri.Host, out literal) ? new IPAddress[] { literal } : Dns.GetHostAddresses(uri.DnsSafeHost);
                dnsMs = (int)sw.ElapsedMilliseconds;
                List<IPAddress> addresses = new List<IPAddress>();
                AddressFamily wanted = bindTo != null ? bindTo.AddressFamily : AddressFamily.InterNetwork;
                foreach (IPAddress a in found) { if (a.AddressFamily == wanted) addresses.Add(a); }
                if (bindTo == null) { foreach (IPAddress a in found) { if (a.AddressFamily != wanted) addresses.Add(a); } }
                if (addresses.Count == 0) return Done(CheckResult.Fail("DNS_FAIL", sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);

                // 2. connect (a second address is tried if the first refuses, as a browser would)
                stage = "CONNECT";
                long connectStart = sw.ElapsedMilliseconds;
                SocketError lastError = SocketError.TimedOut;
                for (int i = 0; i < addresses.Count && i < 2 && s == null; i++)
                {
                    int left = timeoutMs - (int)sw.ElapsedMilliseconds;
                    if (left <= 0) break;
                    Socket candidate = new Socket(addresses[i].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    socket = candidate;
                    try
                    {
                        candidate.NoDelay = true;
                        if (bindTo != null && bindTo.AddressFamily == addresses[i].AddressFamily) candidate.Bind(new IPEndPoint(bindTo, 0));
                        IAsyncResult ar = candidate.BeginConnect(new IPEndPoint(addresses[i], uri.Port), null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(left, false)) { lastError = SocketError.TimedOut; candidate.Close(); continue; }
                        candidate.EndConnect(ar);
                        s = candidate;
                    }
                    catch (SocketException ex) { lastError = ex.SocketErrorCode; try { candidate.Close(); } catch { } }
                }
                if (s == null)
                {
                    string why = lastError == SocketError.TimedOut ? "CONNECT_TIMEOUT"
                               : lastError == SocketError.ConnectionRefused ? "REFUSED"
                               : (lastError == SocketError.NetworkUnreachable || lastError == SocketError.HostUnreachable) ? "UNREACHABLE" : "CONNECT_FAIL";
                    return Done(CheckResult.Fail(why, sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);
                }
                tcpMs = (int)(sw.ElapsedMilliseconds - connectStart);

                NetworkStream ns = new NetworkStream(s, true);
                stream = ns;

                // 3. secure handshake
                if (https)
                {
                    stage = "TLS";
                    long tlsStart = sw.ElapsedMilliseconds;
                    ns.ReadTimeout = ns.WriteTimeout = Math.Max(1, timeoutMs - (int)sw.ElapsedMilliseconds);
                    SslStream ssl = new SslStream(ns, false, delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                    {
                        Cert = CertInfo.From(certificate, chain, errors);
                        return true;        // judged below, so that the certificate is recorded even when it is not trusted
                    });
                    stream = ssl;
                    ssl.AuthenticateAsClient(uri.DnsSafeHost);
                    tlsMs = (int)(sw.ElapsedMilliseconds - tlsStart);
                    if (Cert != null && !Cert.Trusted) return Done(CheckResult.Fail("TLS_ERROR", sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);
                }

                // 4. request and reply. Unique query string so no proxy or cache can answer from memory.
                stage = "RESPONSE";
                ns.ReadTimeout = ns.WriteTimeout = Math.Max(1, timeoutMs - (int)sw.ElapsedMilliseconds);
                string path = uri.PathAndQuery + (uri.PathAndQuery.IndexOf('?') >= 0 ? "&" : "?") + "_cb=" + DateTime.UtcNow.Ticks;
                string head = "GET " + path + " HTTP/1.1\r\nHost: " + (uri.IsDefaultPort ? uri.Host : uri.Host + ":" + uri.Port)
                    + "\r\nUser-Agent: " + UserAgent + "\r\nAccept: */*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\n\r\n";
                byte[] send = Encoding.ASCII.GetBytes(head);
                stream.Write(send, 0, send.Length);
                stream.Flush();

                int code;
                string body;
                if (!ReadReply(stream, target.ExpectText != null, out code, out body))
                    return Done(CheckResult.Fail("UNEXPECTED_CONTENT", sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);
                sw.Stop();

                string bad = StatusFailure(code);
                if (bad != null) return Done(CheckResult.Fail(bad, sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);
                return Done(Judge(code, body, sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);
            }
            catch (Exception ex)
            {
                sw.Stop();
                return Done(CheckResult.Fail(FailureAt(ex), sw.ElapsedMilliseconds), dnsMs, tcpMs, tlsMs);
            }
            finally
            {
                try { if (stream != null) stream.Dispose(); } catch { }
                try { if (s != null) s.Close(); } catch { }
            }
        }

        private static CheckResult Done(CheckResult r, int dnsMs, int tcpMs, int tlsMs)
        {
            r.DnsMs = dnsMs; r.TcpMs = tcpMs; r.TlsMs = tlsMs;
            return r;
        }

        // Turns whatever went wrong into "which stage, and was it a timeout".
        private string FailureAt(Exception ex)
        {
            SocketException se = ex as SocketException;
            for (Exception inner = ex; se == null && inner != null; inner = inner.InnerException) se = inner as SocketException;
            bool timedOut = aborted || (se != null && se.SocketErrorCode == SocketError.TimedOut);
            string at = stage;
            if (at == "DNS") return timedOut ? "DNS_TIMEOUT" : "DNS_FAIL";
            if (at == "CONNECT") return timedOut ? "CONNECT_TIMEOUT" : "CONNECT_FAIL";
            if (at == "TLS")
            {
                if (timedOut) return "TLS_TIMEOUT";
                return ex is System.Security.Authentication.AuthenticationException ? "TLS_ERROR" : "TLS_RESET";
            }
            return timedOut ? "RESPONSE_TIMEOUT" : "CONNECTION_RESET";
        }

        // Reads the status line and headers, and the body too when the check needs to look inside it.
        private static bool ReadReply(Stream stream, bool needBody, out int code, out string body)
        {
            code = 0; body = "";
            byte[] buf = new byte[16384];
            int total = 0, headerEnd = -1;
            long contentLength = -1;
            bool chunked = false;
            while (total < buf.Length)
            {
                int n = stream.Read(buf, total, buf.Length - total);
                if (n <= 0) break;
                total += n;
                if (headerEnd < 0)
                {
                    string soFar = Encoding.ASCII.GetString(buf, 0, total);
                    int end = soFar.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    if (end < 0) continue;
                    headerEnd = end + 4;
                    Match status = Regex.Match(soFar, @"^HTTP/\d\.\d\s+(\d{3})");
                    if (!status.Success) return false;
                    code = int.Parse(status.Groups[1].Value);
                    Match length = Regex.Match(soFar.Substring(0, end), @"(?im)^Content-Length:\s*(\d+)\s*$");
                    if (length.Success) contentLength = long.Parse(length.Groups[1].Value);
                    chunked = Regex.IsMatch(soFar.Substring(0, end), @"(?im)^Transfer-Encoding:.*chunked");
                    if (!needBody || code == 204 || code == 304 || contentLength == 0) break;
                }
                if (contentLength >= 0 && total - headerEnd >= contentLength) break;
                if (chunked && total >= 5 && Encoding.ASCII.GetString(buf, total - 5, 5) == "0\r\n\r\n") break;
            }
            if (headerEnd < 0) return false;
            body = Encoding.UTF8.GetString(buf, headerEnd, total - headerEnd);
            return true;
        }

        private static string StatusFailure(int code)
        {
            if (code < 400) return null;
            if (code == 407) return "PROXY_AUTH";
            if (code == 429) return "RATE_LIMITED";
            if (code == 403 || code == 451) return "BLOCKED";
            if (code == 502 || code == 503 || code == 504) return "GATEWAY_ERROR";
            return "HTTP_" + code;
        }

        // Shared by both routes: does the reply look like the real site?
        private CheckResult Judge(int code, string body, long ms)
        {
            if (code >= 300 && code < 400) return CheckResult.Fail("REDIRECTED", ms);    // a block page or captive portal
            if (target.ExpectStatus > 0 && code != target.ExpectStatus) return CheckResult.Fail("UNEXPECTED_CONTENT", ms);
            if (target.ExpectText != null && body.IndexOf(target.ExpectText, StringComparison.OrdinalIgnoreCase) < 0)
                return CheckResult.Fail("UNEXPECTED_CONTENT", ms);

            Match m = Regex.Match(body, @"(?m)^ip=([0-9a-fA-F\.:]+)\s*$");
            if (m.Success) ExternalIP = m.Groups[1].Value;
            Match colo = Regex.Match(body, @"(?m)^colo=([A-Za-z]{3})\s*$");
            if (colo.Success) ServedFrom = colo.Groups[1].Value.ToUpperInvariant();
            return CheckResult.Pass(ms);
        }

        // ---------------------------------------------------------------- through a configured proxy
        private CheckResult RunViaProxy()
        {
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                string url = target.Url + (target.Url.IndexOf('?') >= 0 ? "&" : "?") + "_cb=" + DateTime.UtcNow.Ticks;
                HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url);
                request = r;
                r.Method = "GET";
                r.Timeout = timeoutMs;
                r.ReadWriteTimeout = timeoutMs;
                r.KeepAlive = false;              // fresh connection every time: tests the whole path
                r.AllowAutoRedirect = false;      // a redirect means a block page or captive portal
                r.UserAgent = UserAgent;
                r.CachePolicy = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore);
                r.Headers[HttpRequestHeader.CacheControl] = "no-cache";
                // Set every time (and cleared when on automatic): .NET keeps one ServicePoint per site between runs.
                r.ServicePoint.BindIPEndPointDelegate = bindTo != null ? new BindIPEndPoint(Bind) : null;

                int code;
                string body;
                using (HttpWebResponse resp = (HttpWebResponse)r.GetResponse())
                {
                    code = (int)resp.StatusCode;
                    body = ReadBody(resp);
                }
                sw.Stop();

                try
                {
                    if (r.ServicePoint != null && r.ServicePoint.Certificate != null) Cert = CertInfo.From(r.ServicePoint.Certificate);
                }
                catch { }
                return Done(Judge(code, body, sw.ElapsedMilliseconds), -1, -1, -1);
            }
            catch (WebException ex)
            {
                sw.Stop();
                return Done(CheckResult.Fail(Classify(ex), sw.ElapsedMilliseconds), -1, -1, -1);
            }
            catch (Exception)
            {
                sw.Stop();
                return Done(CheckResult.Fail("ERROR", sw.ElapsedMilliseconds), -1, -1, -1);
            }
        }

        // Makes the connection leave from the chosen adapter's address, which is what makes
        // Windows send it out through that adapter.
        private IPEndPoint Bind(ServicePoint servicePoint, IPEndPoint remote, int retryCount)
        {
            return bindTo != null && remote.AddressFamily == bindTo.AddressFamily ? new IPEndPoint(bindTo, 0) : null;
        }

        private static string ReadBody(HttpWebResponse resp)
        {
            try
            {
                using (Stream s = resp.GetResponseStream())
                {
                    if (s == null) return "";
                    byte[] buf = new byte[4096];
                    int total = 0, n;
                    while (total < buf.Length && (n = s.Read(buf, total, buf.Length - total)) > 0) total += n;
                    return Encoding.UTF8.GetString(buf, 0, total);
                }
            }
            catch { return ""; }
        }

        // Uses the status enum, not the message text, so it works on any Windows language.
        private static string Classify(WebException ex)
        {
            HttpWebResponse resp = ex.Response as HttpWebResponse;
            if (resp != null)
            {
                int code = (int)resp.StatusCode;
                try { resp.Close(); } catch { }
                return StatusFailure(code) ?? "HTTP_" + code;
            }
            switch (ex.Status)
            {
                case WebExceptionStatus.Timeout:
                case WebExceptionStatus.RequestCanceled: return "TIMEOUT";
                case WebExceptionStatus.NameResolutionFailure: return "DNS_FAIL";
                case WebExceptionStatus.ProxyNameResolutionFailure: return "PROXY_DNS_FAIL";
                case WebExceptionStatus.ConnectFailure: return "CONNECT_FAIL";
                case WebExceptionStatus.TrustFailure:
                case WebExceptionStatus.SecureChannelFailure: return "TLS_ERROR";
                case WebExceptionStatus.ConnectionClosed:
                case WebExceptionStatus.ReceiveFailure:
                case WebExceptionStatus.SendFailure:
                case WebExceptionStatus.KeepAliveFailure: return "CONNECTION_RESET";
                default: return "ERROR";
            }
        }
    }

    internal static class Probes
    {
        public static CheckResult Tcp(string host, int port, int timeoutMs, IPAddress bindTo)
        {
            Stopwatch sw = Stopwatch.StartNew();
            TcpClient client = null;
            try
            {
                IPAddress ip;
                bool literal = IPAddress.TryParse(host, out ip);
                if (bindTo != null && (!literal || ip.AddressFamily == bindTo.AddressFamily)) client = new TcpClient(new IPEndPoint(bindTo, 0));
                else client = literal ? new TcpClient(ip.AddressFamily) : new TcpClient();
                IAsyncResult ar = client.BeginConnect(host, port, null, null);
                bool done = ar.AsyncWaitHandle.WaitOne(timeoutMs, false);
                sw.Stop();
                if (!done) return CheckResult.Fail("TIMEOUT", sw.ElapsedMilliseconds);
                client.EndConnect(ar);
                return client.Connected ? CheckResult.Pass(sw.ElapsedMilliseconds) : CheckResult.Fail("CONNECT_FAIL", sw.ElapsedMilliseconds);
            }
            catch (SocketException ex)
            {
                sw.Stop();
                string d = ex.SocketErrorCode == SocketError.ConnectionRefused ? "REFUSED"
                         : ex.SocketErrorCode == SocketError.HostNotFound ? "DNS_FAIL"
                         : (ex.SocketErrorCode == SocketError.NetworkUnreachable || ex.SocketErrorCode == SocketError.HostUnreachable) ? "UNREACHABLE"
                         : "CONNECT_FAIL";
                return CheckResult.Fail(d, sw.ElapsedMilliseconds);
            }
            catch (Exception)
            {
                sw.Stop();
                return CheckResult.Fail("CONNECT_FAIL", sw.ElapsedMilliseconds);
            }
            finally
            {
                try { if (client != null) client.Close(); } catch { }
            }
        }

        public static CheckResult PingHost(IPAddress address, int timeoutMs)
        {
            // Two attempts: a single lost ping on Wi-Fi should not be called a fault.
            long last = 0;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using (Ping p = new Ping())
                    {
                        PingReply reply = p.Send(address, timeoutMs);
                        if (reply != null && reply.Status == IPStatus.Success) return CheckResult.Pass(reply.RoundtripTime);
                        last = timeoutMs;
                    }
                }
                catch { }
            }
            return CheckResult.Fail("NO_REPLY", last);
        }

        /// <summary>
        /// Sends a real DNS query straight to the configured DNS server over UDP.
        /// Deliberately avoids the Windows resolver, whose cache would keep
        /// answering for minutes after the DNS server itself had gone away.
        /// </summary>
        public static CheckResult Dns(IList<IPAddress> servers, string hostName, int timeoutMs, IPAddress bindTo)
        {
            CheckResult last = CheckResult.Fail("NO_SERVER", 0);
            int tries = Math.Min(2, servers.Count);
            for (int i = 0; i < tries; i++)
            {
                last = DnsOne(servers[i], hostName, timeoutMs, bindTo);
                if (last.Ok) return last;
            }
            return last;
        }

        private static readonly Random Rng = new Random();

        private static CheckResult DnsOne(IPAddress server, string hostName, int timeoutMs, IPAddress bindTo)
        {
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                List<byte> q = new List<byte>(64);
                int id;
                lock (Rng) { id = Rng.Next(1, 65535); }
                q.Add((byte)(id >> 8)); q.Add((byte)(id & 0xFF));
                q.Add(0x01); q.Add(0x00);                       // standard query, recursion desired
                q.Add(0x00); q.Add(0x01);                       // one question
                q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0); q.Add(0);
                foreach (string label in hostName.Split('.'))
                {
                    if (label.Length == 0 || label.Length > 63) continue;
                    q.Add((byte)label.Length);
                    q.AddRange(Encoding.ASCII.GetBytes(label));
                }
                q.Add(0);
                q.Add(0x00); q.Add(0x01);                       // type A
                q.Add(0x00); q.Add(0x01);                       // class IN
                byte[] query = q.ToArray();

                bool bind = bindTo != null && bindTo.AddressFamily == server.AddressFamily;
                using (UdpClient udp = bind ? new UdpClient(new IPEndPoint(bindTo, 0)) : new UdpClient(server.AddressFamily))
                {
                    udp.Client.ReceiveTimeout = timeoutMs;
                    udp.Connect(server, 53);
                    udp.Send(query, query.Length);
                    IPEndPoint from = null;
                    byte[] resp = udp.Receive(ref from);
                    sw.Stop();
                    if (resp.Length < 12 || resp[0] != query[0] || resp[1] != query[1]) return CheckResult.Fail("BAD_REPLY", sw.ElapsedMilliseconds);
                    int rcode = resp[3] & 0x0F;
                    int answers = (resp[6] << 8) | resp[7];
                    if (rcode == 0 && answers > 0) return CheckResult.Pass(sw.ElapsedMilliseconds);
                    if (rcode == 2) return CheckResult.Fail("SERVFAIL", sw.ElapsedMilliseconds);
                    if (rcode == 3) return CheckResult.Fail("NXDOMAIN", sw.ElapsedMilliseconds);
                    if (rcode == 5) return CheckResult.Fail("REFUSED", sw.ElapsedMilliseconds);
                    return CheckResult.Fail("NO_ANSWER", sw.ElapsedMilliseconds);
                }
            }
            catch (SocketException ex)
            {
                sw.Stop();
                return CheckResult.Fail(ex.SocketErrorCode == SocketError.TimedOut ? "TIMEOUT" : "UNREACHABLE", sw.ElapsedMilliseconds);
            }
            catch (Exception)
            {
                sw.Stop();
                return CheckResult.Fail("ERROR", sw.ElapsedMilliseconds);
            }
        }
    }
}
