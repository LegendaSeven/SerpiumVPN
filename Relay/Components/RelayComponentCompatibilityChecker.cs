using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Parser;
using SerpiumVPN.Relay.ProfileVault;
using SerpiumVPN.Relay.Providers;
using SerpiumVPN.Relay.Routing;
using SerpiumVPN.Relay.Xray;

namespace SerpiumVPN.Relay.Components;

/// <summary>Checks production config builders and saved profiles without starting their tunnels.
/// Only synthetic loopback traffic is used for runtime/API/rule reload checks.</summary>
public sealed class RelayComponentCompatibilityChecker
{
    private readonly SecureProfileVault _vault;
    private readonly SecureRoutingRegistry _routing;
    private readonly string _workspace;

    public RelayComponentCompatibilityChecker() : this(new(),new(),Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"SerpiumVPN","Updates","Compatibility")) { }

    public RelayComponentCompatibilityChecker(SecureProfileVault vault, SecureRoutingRegistry routing, string workspace)
    { _vault=vault;_routing=routing;_workspace=Path.GetFullPath(workspace); }

    public async Task ValidateAsync(RelayComponentKind kind,string executable,CancellationToken cancellationToken)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(4));
        CancellationToken token=deadline.Token;
        string directory=Path.Combine(_workspace,Guid.NewGuid().ToString("N"));
        using var rules=new SecureRoutingRuleSetRuntime(directory){FullTunnelWhenEmpty=false};
        try
        {
            var entries=(await _routing.ListAsync(token)).Where(e=>e.Kind==RoutingTargetKind.Application).ToArray();
            await rules.UpdateAsync(entries,kind==RelayComponentKind.XrayCore,token);
            if(kind==RelayComponentKind.XrayCore)
            {
                foreach(var profile in XrayFixtures())
                    await CheckConfigurationAsync(kind,executable,Encoding.UTF8.GetBytes(SerpiumXrayConfigBuilder.Build(profile,10808,"")),token);
            }
            else
            {
                using var bridge=SerpiumRoutingConfigCompiler.BuildXrayBridgeProfile(Guid.NewGuid(),10808,entries,rules.RuleSetPath);
                await CheckConfigurationAsync(kind,executable,bridge.CopyConfiguration(),token);
                using var hy=Hysteria2ProfileFactory.Create(new SerpiumParser().Parse("hy2://compatibility-fixture@127.0.0.1?sni=example.test").Profile!);
                using var compiled=SerpiumRoutingConfigCompiler.CompileProviderProfile(hy,entries,rules.RuleSetPath,applicationSelectionOnly:true);
                await CheckConfigurationAsync(kind,executable,compiled.CopyConfiguration(),token);
            }
            foreach(var entry in await _vault.ListProfilesAsync(token))
            {
                token.ThrowIfCancellationRequested();
                if(kind==RelayComponentKind.XrayCore && entry.Engine.Equals("xray",StringComparison.OrdinalIgnoreCase))
                {
                    var saved=await _vault.OpenXrayProfileAsync(entry.Id,token);
                    await CheckConfigurationAsync(kind,executable,Encoding.UTF8.GetBytes(SerpiumXrayConfigBuilder.Build(saved.Profile,saved.SocksPort,"")),token);
                }
                else if(kind==RelayComponentKind.SingBox && !entry.Engine.Equals("xray",StringComparison.OrdinalIgnoreCase))
                {
                    using var source=await _vault.OpenProviderProfileAsync(entry.Id,token);
                    using var compiled=SerpiumRoutingConfigCompiler.CompileProviderProfile(source,entries,rules.RuleSetPath,applicationSelectionOnly:true);
                    await CheckConfigurationAsync(kind,executable,compiled.CopyConfiguration(),token);
                }
            }
            await CheckLoopbackAsync(kind,executable,directory,token);
        }
        catch(OperationCanceledException) when(!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("Проверка совместимости превысила отведённое время. Рабочая версия сохранена."); }
        finally
        {
            // This task owns only this random directory, never a shared runtime or profile folder.
            try { if(Directory.Exists(directory))Directory.Delete(directory,true); }
            catch(IOException){} catch(UnauthorizedAccessException){}
        }
    }

    private static IEnumerable<SerpiumConnectionProfile> XrayFixtures()
    {
        const string id="00112233-4455-6677-8899-aabbccddeeff";
        yield return new(){Protocol="vless",Server="127.0.0.1",Port=443,UserId=id};
        yield return new(){Protocol="vmess",Server="127.0.0.1",Port=443,UserId=id,Encryption="auto"};
        yield return new(){Protocol="trojan",Server="127.0.0.1",Port=443,Password="compatibility-fixture",Security="tls",ServerName="example.test"};
        using var extra=JsonDocument.Parse("{\"xmux\":{\"maxConcurrency\":\"8-16\"}}");
        yield return new(){Protocol="vless",Server="127.0.0.1",Port=443,UserId=id,Transport="xhttp",Mode="auto",Security="reality",
            ServerName="example.test",PublicKey=Convert.ToBase64String(Enumerable.Repeat((byte)7,32).ToArray()).TrimEnd('=').Replace('+','-').Replace('/','_'),XhttpExtra=extra.RootElement.Clone()};
    }

    private static Process Start(string path,IEnumerable<string> arguments)
    {
        var info=new ProcessStartInfo(path){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Path.GetDirectoryName(Path.GetFullPath(path))!,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(string argument in arguments)info.ArgumentList.Add(argument);
        return Process.Start(info)??throw new IOException("Не удалось запустить проверку компонента.");
    }

    private static async Task DrainAsync(StreamReader reader)
    {
        // Never retain or report native output, which can echo saved credentials.
        char[] buffer=new char[4096];
        try { while(await reader.ReadAsync(buffer)>0)Array.Clear(buffer); }
        catch(IOException){} catch(ObjectDisposedException){}
        finally{Array.Clear(buffer);}
    }

    private static void Kill(Process process)
    {
        try{if(!process.HasExited)process.Kill(true);}
        catch(InvalidOperationException){}catch(System.ComponentModel.Win32Exception){}
    }

    private static async Task FinishAsync(Process process,Task output,Task errors)
    {
        Kill(process);
        try{await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3));await Task.WhenAll(output,errors).WaitAsync(TimeSpan.FromSeconds(3));}
        catch(TimeoutException){}catch(InvalidOperationException){}
    }

    private static async Task CheckConfigurationAsync(RelayComponentKind kind,string path,byte[] config,CancellationToken token)
    {
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(20));
            using var process=Start(path,kind==RelayComponentKind.SingBox?["check","-c","stdin"]:["run","-test","-config","stdin:"]);
            var output=DrainAsync(process.StandardOutput);var errors=DrainAsync(process.StandardError);
            using var stop=deadline.Token.Register(()=>Kill(process));
            try
            {
                try{await process.StandardInput.BaseStream.WriteAsync(config,deadline.Token);process.StandardInput.Close();}
                catch(IOException){deadline.Token.ThrowIfCancellationRequested();}
                await process.WaitForExitAsync(deadline.Token);
                if(process.ExitCode!=0)throw new InvalidDataException("Новая версия не поддерживает конфигурации Serpium или сохранённые профили.");
            }
            finally{await FinishAsync(process,output,errors);}
        }
        finally{CryptographicOperations.ZeroMemory(config);}
    }

    private static int FreePort(){using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();return ((IPEndPoint)listener.LocalEndpoint).Port;}

    private static async Task CheckLoopbackAsync(RelayComponentKind kind,string path,string directory,CancellationToken token)
    {
        int socks=FreePort(),api=FreePort();while(api==socks)api=FreePort();
        string secret=Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),ruleFile=Path.Combine(directory,"compatibility-rules.json");
        await WriteRulesAsync(ruleFile,false,token);
        JsonObject config;
        if(kind==RelayComponentKind.SingBox)
        {
            config=JsonNode.Parse("""{"log":{"level":"error"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":0}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"rule_set":"compat","action":"reject"}],"rule_set":[{"type":"local","tag":"compat","format":"source","path":""}],"final":"direct"},"experimental":{"clash_api":{"external_controller":"","secret":""}}}""")!.AsObject();
            config["inbounds"]![0]!["listen_port"]=socks;
            config["route"]!["rule_set"]![0]!["path"]=ruleFile;
            config["experimental"]!["clash_api"]!["external_controller"]="127.0.0.1:"+api;
            config["experimental"]!["clash_api"]!["secret"]=secret;
        }
        else
        {
            config=JsonNode.Parse(SerpiumXrayConfigBuilder.Build(XrayFixtures().First(),socks,""))!.AsObject();
            config["outbounds"]=new JsonArray(new JsonObject{["protocol"]="freedom",["tag"]="direct"});
        }
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(config);
        using var process=Start(path,kind==RelayComponentKind.SingBox?["run","-c","stdin"]:["run","-config","stdin:"]);
        var output=DrainAsync(process.StandardOutput);var errors=DrainAsync(process.StandardError);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(TimeSpan.FromSeconds(25));
        using var stop=deadline.Token.Register(()=>Kill(process));
        try
        {
            await process.StandardInput.BaseStream.WriteAsync(bytes,deadline.Token);process.StandardInput.Close();
            bool ready=false;
            for(int attempt=0;attempt<60&&!process.HasExited;attempt++)
            {
                using var probe=new TcpClient();
                try{await probe.ConnectAsync(IPAddress.Loopback,socks,deadline.Token);ready=true;break;}
                catch(SocketException){await Task.Delay(100,deadline.Token);}
            }
            if(!ready)throw new InvalidDataException("Компонент не запустил локальный тестовый вход.");
            using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int target=((IPEndPoint)listener.LocalEndpoint).Port;
            using var client=new TcpClient();await client.ConnectAsync(IPAddress.Loopback,socks,deadline.Token);
            if(!await ConnectSocksAsync(client,target,deadline.Token))throw new InvalidDataException("Компонент не прошёл локальную проверку передачи данных.");
            using var accepted=await listener.AcceptTcpClientAsync(deadline.Token);
            byte[] marker="Serpium compatibility"u8.ToArray();await client.GetStream().WriteAsync(marker,deadline.Token);byte[] received=new byte[marker.Length];
            await accepted.GetStream().ReadExactlyAsync(received,deadline.Token);
            if(!received.SequenceEqual(marker))throw new InvalidDataException("Локальная передача данных повреждена.");
            if(kind==RelayComponentKind.SingBox)
            {
                using var http=new HttpClient(new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false}){BaseAddress=new Uri($"http://127.0.0.1:{api}/")};
                using(var unauthorized=await http.GetAsync("connections",deadline.Token))
                    if(unauthorized.StatusCode!=HttpStatusCode.Unauthorized)throw new InvalidDataException("Локальный API не защищён паролем.");
                http.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",secret);
                string? id=null;
                for(int attempt=0;attempt<25 && id is null;attempt++)
                {
                    using var response=await http.GetAsync("connections",deadline.Token);response.EnsureSuccessStatusCode();
                    using var data=JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
                    foreach(var connection in data.RootElement.GetProperty("connections").EnumerateArray())
                        if(connection.GetProperty("metadata").GetProperty("destinationPort").ToString()==target.ToString())id=connection.GetProperty("id").GetString();
                    if(id is null)await Task.Delay(100,deadline.Token);
                }
                if(id is null)throw new InvalidDataException("API не показывает управляемые соединения.");
                using(var closed=await http.DeleteAsync("connections/"+Uri.EscapeDataString(id),deadline.Token))closed.EnsureSuccessStatusCode();
                byte[] eof=new byte[1];int remaining;
                try{remaining=await accepted.GetStream().ReadAsync(eof,deadline.Token);}catch(IOException){remaining=0;}
                if(remaining!=0)throw new InvalidDataException("API не завершил выбранное соединение.");
                await WriteRulesAsync(ruleFile,true,deadline.Token);
                bool rejected=false;
                for(int attempt=0;attempt<30&&!rejected;attempt++)
                {
                    await Task.Delay(150,deadline.Token);using var next=new TcpClient();await next.ConnectAsync(IPAddress.Loopback,socks,deadline.Token);
                    rejected=!await ConnectSocksAsync(next,target,deadline.Token);
                }
                if(!rejected)throw new InvalidDataException("Компонент не применяет правила маршрутизации без перезапуска.");
            }
            token.ThrowIfCancellationRequested();
            if(process.HasExited)throw new InvalidDataException("Компонент завершился во время проверки совместимости.");
        }
        catch(IOException){token.ThrowIfCancellationRequested();throw new InvalidDataException("Компонент не прошёл локальную проверку совместимости.");}
        finally{CryptographicOperations.ZeroMemory(bytes);await FinishAsync(process,output,errors);}
    }

    private static async Task WriteRulesAsync(string path,bool reject,CancellationToken token)
    {
        string temporary=path+".new";
        await File.WriteAllTextAsync(temporary,reject?"""{"version":3,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}""":"""{"version":3,"rules":[{"domain":["compatibility.invalid"]}]}""",token);
        File.Move(temporary,path,true);
    }

    private static async Task<bool> ConnectSocksAsync(TcpClient client,int port,CancellationToken token)
    {
        var stream=client.GetStream();await stream.WriteAsync(new byte[]{5,1,0},token);byte[] hello=new byte[2];await stream.ReadExactlyAsync(hello,token);
        if(hello[0]!=5||hello[1]!=0)return false;
        await stream.WriteAsync(new byte[]{5,1,0,1,127,0,0,1,(byte)(port>>8),(byte)port},token);byte[] reply=new byte[4];
        try{await stream.ReadExactlyAsync(reply,token);}catch(EndOfStreamException){return false;}
        if(reply[0]!=5||reply[1]!=0)return false;
        int length=reply[3] switch{1=>4,4=>16,_=>throw new InvalidDataException("Неверный ответ тестового SOCKS-входа.")};
        await stream.ReadExactlyAsync(new byte[length+2],token);return true;
    }
}
