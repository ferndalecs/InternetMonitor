# Internet Monitor

A small Windows program for school IT staff. It watches the internet connection and the
web filter / proxy, works out **where** a fault is, and produces an HTML report with charts
that you can send to your ISP or filtering provider as evidence.

- One EXE. Nothing to install, no administrator rights, runs as a normal domain user.
- Needs only .NET Framework 4.x, which is part of Windows 10 and 11.
- Sends nothing anywhere: logs and reports are saved as files next to the EXE.

## Download

Get `InternetMonitor.zip` from the [latest release](../../releases/latest), unzip it and run
`InternetMonitor.exe`. The release notes give the SHA-256 of the EXE so you can check your copy.

The EXE is **not code-signed yet**, so Windows SmartScreen may say "Windows protected your PC"
the first time: choose *More info*, then *Run anyway*. If your school only allows signed
software (AppLocker / WDAC), allow it by file hash or build it yourself from this source.

## Using it

1. Pick **Check frequency** and **Run for**, then press **Start monitoring**.
   On a computer with two network connections, also pick the **Network adapter** to test
   (see [Two network connections](#two-network-connections) below).
2. Leave the window open. The status light, figures and chart update live.
3. Press **Stop monitoring**, or let the run finish. A report is saved and offered to you.

**View report** can also build a report from saved logs (today, last 7 or 30 days), and a
**combined report** for every computer saving to the same folder.

Files are saved next to the EXE in `Logs\` (CSV, one per computer per day, plus route
traces and certificate records) and `Reports\` (HTML). If that folder is read-only, the user's `Documents\InternetMonitor` is used instead.

## What it checks

Each round, all of these run at the same moment:

| Check | What it tells you |
|---|---|
| Web requests to Google, Microsoft, Cloudflare and Gstatic | What a browser experiences, through the web filter / proxy. Each is timed in stages: name lookup, connecting, secure handshake, reply |
| Each site's certificate | Whether the web filter is decrypting that site (HTTPS inspection) |
| Service check: Hwb | Whether Hwb answers. Once a minute only, and reported separately |
| Direct connections (port 443) to Cloudflare, Google and Quad9 | Whether the internet line is up, bypassing a configured proxy |
| Ping to the default gateway | Whether the local network / Wi-Fi is up |
| DNS query | Whether the DNS server answers |
| Proxy port | Whether the configured proxy is reachable (only if Windows has one set) |

From the combination it reaches one conclusion:

| Conclusion | Meaning |
|---|---|
| Online | All web checks succeed |
| Degraded | Some web checks fail, others succeed |
| HTTPS inspection fault | The sites the web filter decrypts fail; sites it does not decrypt, and the connection underneath, still work |
| Web filter / proxy fault | Web fails, but direct connections work |
| Internet outage | Web and direct connections fail; the local network is fine |
| Web access down | Web fails, and direct connections are never allowed here, so proxy and line cannot be told apart |
| DNS failure | Names cannot be resolved |
| Local network fault | The computer cannot reach its own gateway |
| Not connected | No active network adapter |

**Degraded is not downtime.** Availability only falls when *every* web check fails at once.
If one website keeps failing while the others answer, availability stays at 100%, so that
case is shown separately: the window has a **Degraded** tile and a **Success** column giving
each check's success rate, and the report has a section listing every website that failed
while the connection was up, including whether the failures recur on a regular cycle.

## HTTPS inspection

Many school web filters decrypt secure (HTTPS) traffic so that they can inspect it. The filter
answers in place of the real website and presents a certificate of its own. When that part of
the filter stalls, secure websites hang even though the internet line is working perfectly,
and it is easily mistaken for "the internet is slow" or "Google is down".

The monitor is built to catch and prove this:

- **It reads every site's certificate** and works out whether it came from the site's real
  certificate authority or from a filter. Decrypted sites are marked *decrypted by filter* in
  the window. Each certificate issuer is saved, word for word, in `Logs\InternetCerts_*.csv`.
- **It times each web request in stages.** A line fault stops the connection being made. An
  inspection fault looks different: the connection is made in a couple of milliseconds, then
  the secure handshake never completes. The stage is in the log for every request.
  On a computer that uses a proxy the request is made through it, as a browser's is, and there
  is one more stage: asking the proxy for a path to the site and waiting for its go-ahead. A
  filter that decrypts at the proxy tends to stall there instead (`TUNNEL_TIMEOUT` in the log).
- **It compares decrypted sites with ones that are not.** Gstatic (the address Android uses
  to test its connection) is normally left alone by filters, and the Microsoft check is plain
  HTTP, so both keep working during an inspection fault.

When every decrypted site fails while the others carry on, the conclusion is **HTTPS
inspection fault**, and it counts as downtime. The report then has an *HTTPS inspection*
section giving the evidence: who issued each certificate, how many checks failed on decrypted
sites against sites that are not decrypted, what else was working in the same seconds (direct
connections, DNS, the gateway), the stage at which the requests failed, and whether the faults
come round on a regular cycle.

At least two decrypted sites must fail together before this conclusion is reached; one site
failing alone is reported as Degraded.

If the proxy asks for a sign-in, Windows' own web client makes the requests instead, because
only it can sign in as the logged-on user. Certificates are still read for every site, but
those requests cannot be timed in stages; the report's *Proxy* line says when this applies.

It also records:

- **The public IP address** the network is seen as (read from Cloudflare's reply). It is shown
  in the window and at the top of the report, which also lists any changes of address.

- **A route trace** while healthy and again the moment each outage begins, so the report
  can say at which router the replies stopped.
- **Wi-Fi signal and access point**, to separate "the internet dropped" from "this laptop
  roamed or had poor signal". Windows only releases these when Location services are on.
  The program checks that setting quietly and never causes a Windows prompt; when Location
  is off or blocked by Group Policy it records Wi-Fi link speed instead.

## Two network connections

A computer with two connections that both lead to the internet (two lines, or wired plus
Wi-Fi) lets Windows decide which one each request uses, and that can differ from one request
to the next. Left on **Automatic**, the monitor's results are then a blend of both, and the
report says so.

Choose an adapter under **Network adapter** to send every check out through that one
connection: the web requests, the direct connections, the DNS query (to that adapter's own
DNS server), the gateway ping and the route trace. The public IP address shown is then that
connection's. Run once on each adapter to compare two lines. Each row of the log records the
adapter it used.

Two limits: website names are still looked up by Windows, which may ask either connection's
DNS server; and if the chosen adapter is unplugged the monitor reports *Not connected* rather
than quietly switching to the other one.

## Is it safe to leave running?

It is built so that it does not look like an attack on anybody's servers:

- The frequent web checks only use endpoints that suit automatic connectivity testing
  (Google's and Microsoft's are the ones Android, Chrome and Windows poll themselves).
- Any ordinary website, such as Hwb, is a *service check*: one tiny request a minute, never
  faster during an outage, and never counted towards Online / Outage.
- A site that answers `429 Too Many Requests` is left alone for 15 minutes.
- Every request identifies itself as `InternetMonitor/<version> (school connectivity monitor)`.

On the default **Adaptive** setting one computer sends about 12 requests a minute to each of
Google, Gstatic (also Google's), Microsoft and Cloudflare (every 5 seconds, speeding up to every second only while a
problem is happening). Please do not leave *Every second* running on many computers for days.

Although Google, Microsoft and Cloudflare are American companies, they answer from their
nearest site, which from Wales is normally London. The report shows which site answered.

## Several computers, one report

Run the program on several computers with `DataFolder` (see below) pointing at the same
network share. Then, on any one of them, choose **View report > All computers**.

The combined report puts every computer on one timeline and sorts outages into:

- **Site-wide**: at least two computers, and at least half of those monitoring at the time,
  went down together. That points at the line, firewall or web filter.
- **Local**: only a minority were affected. That points at Wi-Fi, cabling or the computer.

To compare several schools, use **All computers: choose a folder** and give each school its
own sub-folder; outages are only ever compared within a school.

This uses ordinary file sharing. The program never listens on the network, so Windows
Firewall on the monitoring computers needs no changes.

## Settings (optional)

Rename `InternetMonitor.sample.ini` to `InternetMonitor.ini`, keep it beside the EXE, and
remove the `#` from the lines you want. The file explains each setting. The most useful:

```ini
Organisation = Example School
DataFolder   = \\server\share\InternetMonitor
Contact      = it-support@example.sch.uk
```

For unattended runs:

```
InternetMonitor.exe /start /interval:adaptive /duration:480 /minimized
InternetMonitor.exe /start "/adapter:Ethernet 2"
```

`/adapter:` takes the adapter's name or its IP address (or `auto`). If the named adapter is
not found, monitoring does not start, so a report is never made about the wrong connection.

## Privacy

Logs and reports contain the computer name, local and public IP addresses, Wi-Fi network
and access point, the names on the certificates websites presented (which can name your
filtering provider), and (in reports) the signed-in username. Treat a shared data folder
accordingly, and check a report before sending it outside your organisation.

## Building from source

```
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

This uses the C# compiler that is built in to Windows, so no Visual Studio or SDK is needed
(which is also why the code sticks to C# 5 syntax). The result is `dist\InternetMonitor.exe`.

| File | Contents |
|---|---|
| `src/Core.cs` | Settings, status codes, network discovery, the individual probes, certificate checks |
| `src/Engine.cs` | Sampling loop, the diagnosis rules (`Diagnosis.Classify`), CSV logs |
| `src/Extras.cs` | Wi-Fi details and route tracing |
| `src/Report.cs`, `src/FleetReport.cs` | Calculations for the single and combined reports |
| `src/ReportTemplate.html` | Report layout and charts (embedded in the EXE; no external files) |
| `src/MainForm.cs`, `src/Program.cs` | The window and start-up |
