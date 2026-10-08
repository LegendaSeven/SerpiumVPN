#requires -version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReadyPath,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$ParentPid,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{32}$')]
    [string]$RunToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$readyFullPath = [IO.Path]::GetFullPath($ReadyPath)
$readyParent = Split-Path -Parent $readyFullPath

if ([string]::IsNullOrWhiteSpace($readyParent)) {
    throw "ReadyPath must have a parent directory."
}

New-Item -ItemType Directory -Path $readyParent -Force | Out-Null
$stopPath = $readyFullPath + ".stop"
Remove-Item -LiteralPath $readyFullPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $stopPath -Force -ErrorAction SilentlyContinue

if ($null -eq ("Serpium.Wfp4a.LocalRouteTestBackend" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Serpium.Wfp4a
{
    public sealed class LocalRouteTestBackend : IDisposable
    {
        private readonly object sync = new object();
        private readonly List<TcpClient> clients = new List<TcpClient>();
        private volatile bool stopping;
        private TcpListener socks;
        private TcpListener echoV4;
        private TcpListener echoV6;

        public int SocksPort { get; private set; }
        public int EchoV4Port { get; private set; }
        public int EchoV6Port { get; private set; }
        public string AddressV4 { get; private set; }
        public string AddressV6 { get; private set; }

        public void Start()
        {
            IPAddress addressV4 = SelectAddress(AddressFamily.InterNetwork);

            if (addressV4 == null)
            {
                throw new InvalidOperationException(
                    "No operational non-loopback IPv4 address is available."
                    );
            }

            IPAddress addressV6 = SelectAddress(AddressFamily.InterNetworkV6);
            AddressV4 = addressV4.ToString();
            AddressV6 = addressV6 == null ? null : addressV6.ToString();

            socks = new TcpListener(IPAddress.Loopback, 0);
            socks.Start(32);
            SocksPort = ((IPEndPoint)socks.LocalEndpoint).Port;

            echoV4 = new TcpListener(addressV4, 0);
            echoV4.Start(32);
            EchoV4Port = ((IPEndPoint)echoV4.LocalEndpoint).Port;

            if (addressV6 != null)
            {
                echoV6 = new TcpListener(addressV6, 0);
                echoV6.Server.SetSocketOption(
                    SocketOptionLevel.IPv6,
                    SocketOptionName.IPv6Only,
                    true
                    );
                echoV6.Start(32);
                EchoV6Port = ((IPEndPoint)echoV6.LocalEndpoint).Port;
            }

            Task.Run(() => AcceptLoop(socks, true));
            Task.Run(() => AcceptLoop(echoV4, false));

            if (echoV6 != null)
            {
                Task.Run(() => AcceptLoop(echoV6, false));
            }
        }

        private static int InterfaceRank(NetworkInterface adapter)
        {
            if (adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
            {
                return 0;
            }

            if (adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
            {
                return 1;
            }

            if (adapter.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet)
            {
                return 2;
            }

            return 10;
        }

        private static IPAddress SelectAddress(AddressFamily family)
        {
            List<Tuple<int, IPAddress>> candidates =
                new List<Tuple<int, IPAddress>>();

            foreach (NetworkInterface adapter in
                     NetworkInterface.GetAllNetworkInterfaces())
            {
                if (
                    adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel
                    )
                {
                    continue;
                }

                foreach (UnicastIPAddressInformation unicast in
                         adapter.GetIPProperties().UnicastAddresses)
                {
                    IPAddress address = unicast.Address;

                    if (address.AddressFamily != family)
                    {
                        continue;
                    }

                    if (family == AddressFamily.InterNetwork)
                    {
                        byte[] bytes = address.GetAddressBytes();

                        if (
                            address.Equals(IPAddress.Any) ||
                            address.Equals(IPAddress.Loopback) ||
                            bytes[0] == 127
                            )
                        {
                            continue;
                        }

                        int linkLocalPenalty =
                            bytes[0] == 169 && bytes[1] == 254 ? 20 : 0;
                        candidates.Add(
                            Tuple.Create(
                                InterfaceRank(adapter) + linkLocalPenalty,
                                address
                                )
                            );
                    }
                    else
                    {
                        if (
                            address.Equals(IPAddress.IPv6Any) ||
                            address.Equals(IPAddress.IPv6Loopback) ||
                            address.IsIPv6Multicast
                            )
                        {
                            continue;
                        }

                        int linkLocalPenalty = address.IsIPv6LinkLocal ? 10 : 0;
                        candidates.Add(
                            Tuple.Create(
                                InterfaceRank(adapter) + linkLocalPenalty,
                                address
                                )
                            );
                    }
                }
            }

            return candidates
                .OrderBy(item => item.Item1)
                .ThenBy(item => item.Item2.ToString(), StringComparer.Ordinal)
                .Select(item => item.Item2)
                .FirstOrDefault();
        }

        private void AcceptLoop(TcpListener listener, bool socksMode)
        {
            while (!stopping)
            {
                TcpClient client = null;

                try
                {
                    client = listener.AcceptTcpClient();
                    client.NoDelay = true;
                    client.ReceiveTimeout = 10000;
                    client.SendTimeout = 10000;

                    lock (sync)
                    {
                        clients.Add(client);
                    }

                    TcpClient captured = client;
                    Task.Run(() => HandleClient(captured, socksMode));
                }
                catch (SocketException)
                {
                    if (!stopping)
                    {
                        Thread.Sleep(50);
                    }
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
            }
        }

        private void HandleClient(TcpClient client, bool socksMode)
        {
            try
            {
                using (client)
                using (NetworkStream stream = client.GetStream())
                {
                    if (!socksMode && !IsLocalEchoClient(client))
                    {
                        return;
                    }

                    if (socksMode && !PerformSocksHandshake(stream))
                    {
                        return;
                    }

                    Echo(stream);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                lock (sync)
                {
                    clients.Remove(client);
                }
            }
        }

        private bool IsLocalEchoClient(TcpClient client)
        {
            IPEndPoint remote = client.Client.RemoteEndPoint as IPEndPoint;

            if (remote == null)
            {
                return false;
            }

            if (remote.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                return remote.Address.GetAddressBytes().SequenceEqual(
                    IPAddress.Parse(AddressV4).GetAddressBytes()
                    );
            }

            return
                !String.IsNullOrEmpty(AddressV6) &&
                remote.Address.GetAddressBytes().SequenceEqual(
                    IPAddress.Parse(AddressV6).GetAddressBytes()
                    );
        }

        private bool PerformSocksHandshake(NetworkStream stream)
        {
            byte[] greetingHeader = new byte[2];

            if (!ReadExact(stream, greetingHeader, 0, 2))
            {
                return false;
            }

            if (greetingHeader[0] != 5 || greetingHeader[1] == 0)
            {
                return false;
            }

            byte[] methods = new byte[greetingHeader[1]];

            if (!ReadExact(stream, methods, 0, methods.Length))
            {
                return false;
            }

            bool noAuthentication = Array.IndexOf(methods, (byte)0) >= 0;
            byte[] greetingReply =
                new byte[] { 5, noAuthentication ? (byte)0 : (byte)255 };
            stream.Write(greetingReply, 0, greetingReply.Length);
            stream.Flush();

            if (!noAuthentication)
            {
                return false;
            }

            byte[] requestHeader = new byte[4];

            // The bridge health probe intentionally closes after the greeting.
            if (!ReadExact(stream, requestHeader, 0, requestHeader.Length))
            {
                return false;
            }

            if (
                requestHeader[0] != 5 ||
                requestHeader[1] != 1 ||
                requestHeader[2] != 0 ||
                (requestHeader[3] != 1 && requestHeader[3] != 4)
                )
            {
                SendSocksReply(stream, 7);
                return false;
            }

            int addressLength = requestHeader[3] == 1 ? 4 : 16;
            byte[] addressBytes = new byte[addressLength];
            byte[] portBytes = new byte[2];

            if (
                !ReadExact(stream, addressBytes, 0, addressBytes.Length) ||
                !ReadExact(stream, portBytes, 0, portBytes.Length)
                )
            {
                return false;
            }

            IPAddress requestedAddress = new IPAddress(addressBytes);
            int requestedPort = (portBytes[0] << 8) | portBytes[1];
            bool approved = false;

            if (requestHeader[3] == 1)
            {
                approved =
                    requestedPort == EchoV4Port &&
                    requestedAddress.GetAddressBytes().SequenceEqual(
                        IPAddress.Parse(AddressV4).GetAddressBytes()
                        );
            }
            else if (!String.IsNullOrEmpty(AddressV6))
            {
                approved =
                    requestedPort == EchoV6Port &&
                    requestedAddress.GetAddressBytes().SequenceEqual(
                        IPAddress.Parse(AddressV6).GetAddressBytes()
                        );
            }

            if (!approved)
            {
                SendSocksReply(stream, 2);
                return false;
            }

            SendSocksReply(stream, 0);
            return true;
        }

        private static void SendSocksReply(NetworkStream stream, byte reply)
        {
            byte[] response = new byte[] { 5, reply, 0, 1, 0, 0, 0, 0, 0, 0 };
            stream.Write(response, 0, response.Length);
            stream.Flush();
        }

        private static void Echo(NetworkStream stream)
        {
            byte[] buffer = new byte[16384];

            while (true)
            {
                int received = stream.Read(buffer, 0, buffer.Length);

                if (received <= 0)
                {
                    return;
                }

                stream.Write(buffer, 0, received);
                stream.Flush();
            }
        }

        private static bool ReadExact(
            NetworkStream stream,
            byte[] buffer,
            int offset,
            int count
            )
        {
            int total = 0;

            try
            {
                while (total < count)
                {
                    int received = stream.Read(
                        buffer,
                        offset + total,
                        count - total
                        );

                    if (received <= 0)
                    {
                        return false;
                    }

                    total += received;
                }
            }
            catch (IOException)
            {
                return false;
            }
            catch (SocketException)
            {
                return false;
            }

            return true;
        }

        public void Dispose()
        {
            stopping = true;

            if (socks != null)
            {
                socks.Stop();
            }

            if (echoV4 != null)
            {
                echoV4.Stop();
            }

            if (echoV6 != null)
            {
                echoV6.Stop();
            }

            lock (sync)
            {
                foreach (TcpClient client in clients.ToArray())
                {
                    try
                    {
                        client.Close();
                    }
                    catch (Exception)
                    {
                    }
                }

                clients.Clear();
            }
        }
    }
}
'@
}

$backend = New-Object Serpium.Wfp4a.LocalRouteTestBackend

try {
    $backend.Start()

    $ready = [ordered]@{
        schema = 1
        runToken = $RunToken.ToLowerInvariant()
        processId = $PID
        parentProcessId = $ParentPid
        socksPort = $backend.SocksPort
        addressV4 = $backend.AddressV4
        echoV4Port = $backend.EchoV4Port
        addressV6 = $backend.AddressV6
        echoV6Port = $backend.EchoV6Port
        networkScope = "local-machine-only"
        socksPolicy = "no-auth-exact-test-endpoints-only"
    }
    $readyJson = $ready | ConvertTo-Json -Depth 4
    $temporaryReady = $readyFullPath + ".tmp-" + [guid]::NewGuid().ToString("N")
    [IO.File]::WriteAllText(
        $temporaryReady,
        $readyJson,
        (New-Object System.Text.UTF8Encoding($false))
    )
    Move-Item -LiteralPath $temporaryReady -Destination $readyFullPath -Force

    while (-not (Test-Path -LiteralPath $stopPath -PathType Leaf)) {
        if ($null -eq (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) {
            break
        }

        Start-Sleep -Milliseconds 200
    }
}
finally {
    $backend.Dispose()
    Remove-Item -LiteralPath $readyFullPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stopPath -Force -ErrorAction SilentlyContinue
}
