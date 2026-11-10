// Internet Monitor - Wi-Fi details and route tracing.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace InternetMonitor
{
    // ------------------------------------------------------------------
    // Wi-Fi: which network and access point, and how strong the signal is
    // ------------------------------------------------------------------
    internal sealed class WifiInfo
    {
        public string Ssid = "";
        public string Bssid = "";     // the access point's radio address
        public int Signal = -1;       // 0-100 %, as shown by the Windows Wi-Fi bars
    }

    internal static class Wifi
    {
        /// <summary>True when Windows refused to give Wi-Fi details (Location services switched off).</summary>
        public static volatile bool AccessDenied;

        /// <summary>
        /// Whether the Wi-Fi API may be called at all. Since Windows 11 24H2, asking for the access
        /// point makes Windows show a "location" prompt when Location is off. This program must never
        /// cause that prompt, so the answer is read quietly from the registry first and the API is
        /// only touched when access is already allowed.
        /// </summary>
        public static bool Allowed;
        public static string WhyNot = "";

        public static void Decide(string mode)
        {
            if (mode == "off") { Allowed = false; WhyNot = "switched off in InternetMonitor.ini"; return; }
            if (mode == "on") { Allowed = true; return; }
            try
            {
                const string consent = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location";
                object policy = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", null);
                object appPolicy = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsAccessLocation", null);
                string machine = Registry.GetValue(@"HKEY_LOCAL_MACHINE\" + consent, "Value", null) as string;
                string user = Registry.GetValue(@"HKEY_CURRENT_USER\" + consent, "Value", null) as string;
                string desktop = Registry.GetValue(@"HKEY_CURRENT_USER\" + consent + @"\NonPackaged", "Value", null) as string;

                if (policy is int && (int)policy == 1) { WhyNot = "Location is disabled by Group Policy"; return; }
                if (appPolicy is int && (int)appPolicy == 2) { WhyNot = "app access to Location is denied by Group Policy"; return; }
                if (machine == null && user == null) { Allowed = true; return; }     // older Windows: no such gate
                if (machine != "Allow" || user != "Allow" || desktop == "Deny") { WhyNot = "Windows Location services are switched off"; return; }
                Allowed = true;
            }
            catch { WhyNot = "the Location setting could not be read"; }
        }
        private static bool unavailable;
        private static IntPtr handle = IntPtr.Zero;
        private static readonly object gate = new object();

        [DllImport("wlanapi.dll")]
        private static extern uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);
        [DllImport("wlanapi.dll")]
        private static extern uint WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);
        [DllImport("wlanapi.dll")]
        private static extern uint WlanQueryInterface(IntPtr clientHandle, ref Guid interfaceGuid, int opCode, IntPtr reserved, out int dataSize, out IntPtr data, IntPtr valueType);
        [DllImport("wlanapi.dll")]
        private static extern void WlanFreeMemory(IntPtr memory);

        private const int OpCurrentConnection = 7;
        private const int StateConnected = 1;
        private const uint ErrorAccessDenied = 5;

        /// <summary>Returns the current Wi-Fi connection, or null when there is none or it cannot be read. Never throws.</summary>
        public static WifiInfo Query()
        {
            lock (gate)
            {
                if (unavailable || !Allowed) return null;
                IntPtr list = IntPtr.Zero;
                try
                {
                    if (handle == IntPtr.Zero)
                    {
                        uint negotiated;
                        if (WlanOpenHandle(2, IntPtr.Zero, out negotiated, out handle) != 0) { unavailable = true; return null; }
                    }
                    if (WlanEnumInterfaces(handle, IntPtr.Zero, out list) != 0) return null;

                    // WLAN_INTERFACE_INFO_LIST: count, index, then entries of { GUID, WCHAR[256] description, state }
                    int count = Marshal.ReadInt32(list, 0);
                    const int entrySize = 16 + 512 + 4;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr entry = new IntPtr(list.ToInt64() + 8 + (long)i * entrySize);
                        int state = Marshal.ReadInt32(entry, 16 + 512);
                        if (state != StateConnected) continue;
                        Guid id = (Guid)Marshal.PtrToStructure(entry, typeof(Guid));

                        int size; IntPtr data;
                        uint rc = WlanQueryInterface(handle, ref id, OpCurrentConnection, IntPtr.Zero, out size, out data, IntPtr.Zero);
                        if (rc == ErrorAccessDenied) { AccessDenied = true; continue; }
                        if (rc != 0 || data == IntPtr.Zero) continue;
                        try
                        {
                            // WLAN_CONNECTION_ATTRIBUTES: state(4) mode(4) profile WCHAR[256](512), then the
                            // association block: ssidLen(4) ssid[32] bssType(4) bssid[6] pad(2) phy(4) phyIndex(4) signal(4)
                            if (size < 580) continue;
                            AccessDenied = false;
                            const int assoc = 520;
                            int ssidLen = Math.Min(32, Math.Max(0, Marshal.ReadInt32(data, assoc)));
                            byte[] ssid = new byte[ssidLen];
                            Marshal.Copy(new IntPtr(data.ToInt64() + assoc + 4), ssid, 0, ssidLen);
                            byte[] mac = new byte[6];
                            Marshal.Copy(new IntPtr(data.ToInt64() + assoc + 40), mac, 0, 6);

                            WifiInfo w = new WifiInfo();
                            w.Ssid = Encoding.UTF8.GetString(ssid).Replace(',', ' ').Replace('\r', ' ').Replace('\n', ' ').Trim();
                            w.Bssid = BitConverter.ToString(mac).Replace('-', ':').ToLowerInvariant();
                            w.Signal = Math.Max(0, Math.Min(100, Marshal.ReadInt32(data, assoc + 56)));
                            return w;
                        }
                        finally { WlanFreeMemory(data); }
                    }
                    return null;
                }
                catch (DllNotFoundException) { unavailable = true; return null; }      // no Wi-Fi service on this edition of Windows
                catch (EntryPointNotFoundException) { unavailable = true; return null; }
                catch { return null; }
                finally { if (list != IntPtr.Zero) { try { WlanFreeMemory(list); } catch { } } }
            }
        }
    }

    // ------------------------------------------------------------------
    // Route trace: which routers answer on the way out to the internet
    // ------------------------------------------------------------------
    internal sealed class TraceHop
    {
        public int Hop;
        public string Address = "";   // empty = nothing answered at this hop
        public int Ms = -1;
    }

    internal sealed class Trace
    {
        public DateTime Time;
        public string Reason = "";    // BASELINE or OUTAGE
        public string Target = "";
        public bool Reached;
        public List<TraceHop> Hops = new List<TraceHop>();

        /// <summary>Highest hop number that answered, or 0 when none did.</summary>
        public int LastAnswering
        {
            get { int n = 0; foreach (TraceHop h in Hops) { if (h.Address.Length > 0 && h.Hop > n) n = h.Hop; } return n; }
        }

        public TraceHop At(int hop)
        {
            foreach (TraceHop h in Hops) { if (h.Hop == hop) return h; }
            return null;
        }
    }

    internal static class TraceRoute
    {
        public const string DefaultTarget = "1.1.1.1";
        private const int MaxHops = 20;

        /// <summary>
        /// A traceroute using ordinary pings with a limited hop count (no administrator rights
        /// needed). All hops are probed at once, so it finishes in about a second and can be
        /// taken at the very moment an outage starts.
        /// </summary>
        public static Trace Run(string target, string reason, int timeoutMs)
        {
            Trace trace = new Trace();
            trace.Time = DateTime.Now;
            trace.Reason = reason;
            trace.Target = target;
            try
            {
                IPAddress address = IPAddress.Parse(target);
                Task<TraceHop>[] tasks = new Task<TraceHop>[MaxHops];
                bool[] reached = new bool[MaxHops];
                for (int i = 0; i < MaxHops; i++)
                {
                    int ttl = i + 1;
                    tasks[i] = Task.Factory.StartNew<TraceHop>(delegate
                    {
                        TraceHop hop = new TraceHop();
                        hop.Hop = ttl;
                        try
                        {
                            using (Ping ping = new Ping())
                            {
                                Stopwatch sw = Stopwatch.StartNew();
                                PingReply reply = ping.Send(address, timeoutMs, new byte[32], new PingOptions(ttl, true));
                                sw.Stop();
                                if (reply != null && (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success) && reply.Address != null)
                                {
                                    hop.Address = reply.Address.ToString();
                                    hop.Ms = (int)sw.ElapsedMilliseconds;
                                    if (reply.Status == IPStatus.Success) reached[ttl - 1] = true;
                                }
                            }
                        }
                        catch { }
                        return hop;
                    }, TaskCreationOptions.LongRunning);
                }
                try { Task.WaitAll(tasks, timeoutMs + 2000); } catch { }

                int last = MaxHops;
                for (int i = 0; i < MaxHops; i++) { if (reached[i]) { last = i + 1; trace.Reached = true; break; } }
                for (int i = 0; i < last; i++)
                {
                    TraceHop hop = tasks[i].Status == TaskStatus.RanToCompletion ? tasks[i].Result : null;
                    if (hop == null) { hop = new TraceHop(); hop.Hop = i + 1; }
                    trace.Hops.Add(hop);
                }
                // When the far end was not reached, drop the silent tail after the last router that answered.
                if (!trace.Reached)
                {
                    int keep = Math.Min(trace.Hops.Count, trace.LastAnswering + 1);
                    trace.Hops.RemoveRange(keep, trace.Hops.Count - keep);
                }
            }
            catch { }
            return trace;
        }
    }
}
