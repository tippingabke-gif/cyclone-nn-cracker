using System;

using System.Collections.Generic;

using System.Diagnostics;

using System.Drawing;

using System.IO;

using System.IO.Compression;

using System.Reflection;

using System.Security.Cryptography;

using System.Text;

using System.Threading;

using System.Web.Script.Serialization;

using System.Windows.Forms;

using Microsoft.Win32;



namespace BackendOPT {

public sealed class Session {

    public string engine, session, startedFileTime, filter, debugger, parent, marker;

    public int pid;

    public bool hadUseFilter;

    public int oldUseFilter;

}



public static class RuntimeBundle {

    static Dictionary<string,string> Manifest() {

        using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("RuntimeOPTManifest.json"))

        using(var reader=new StreamReader(stream,Encoding.UTF8))

            return new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(reader.ReadToEnd());

    }

    static string Hash(string file) {

        using(var hash=SHA256.Create()) using(var stream=File.OpenRead(file))

            return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();

    }

    static string Child(string root,string relative) {

        string prefix=Path.GetFullPath(root).TrimEnd('\\')+"\\";

        string file=Path.GetFullPath(Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar)));

        if(!file.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)) throw new Exception("Invalid runtime bundle path");

        return file;

    }

    static void Validate(string root,Dictionary<string,string> manifest) {

        foreach(var entry in manifest) {

            string file=Child(root,entry.Key);

            if(!File.Exists(file) || Hash(file)!=entry.Value) throw new Exception("辅助目录文件校验失败："+entry.Key+"。请关闭助手后将 CycloneSupport-v406-OPT 目录移开，再重新启动。");

        }

    }

    public static void Ensure() {

        var manifest=Manifest();

        if(Directory.Exists(Controller.Root)) {Validate(Controller.Root,manifest);return;}

        string stage=Path.Combine(Controller.AppRoot,"CycloneSupport-v406-OPT.new-"+Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(stage);

        // Both staging and destination are fixed children of this executable's folder.

        Child(Controller.AppRoot,Path.GetFileName(stage));Child(Controller.AppRoot,Path.GetFileName(Controller.Root));

        using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("RuntimeOPT.zip"))

        using(var zip=new ZipArchive(stream,ZipArchiveMode.Read)) {

            foreach(var item in zip.Entries) {

                if(!manifest.ContainsKey(item.FullName)) throw new Exception("Unexpected runtime bundle entry");

                string file=Child(stage,item.FullName);Directory.CreateDirectory(Path.GetDirectoryName(file));

                using(var input=item.Open()) using(var output=new FileStream(file,FileMode.CreateNew,FileAccess.Write)) input.CopyTo(output);

            }

        }

        Validate(stage,manifest);

        Directory.Move(stage,Controller.Root);

    }

}



public static class Controller {

    public static readonly string AppRoot=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

    public static readonly string Root=Path.Combine(AppRoot,"CycloneSupport-v406-OPT");

    public static string NearbyEngine {get {return Path.Combine(AppRoot,"cyclone-nn-opt.exe");}}

    static readonly string State=Path.Combine(Root,"active-session.json");

    const string Ifeo=@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    const string Expected="4c24cb042e796027603b5d3cd4fdc09deab17e63147360602c087724602a4569";

    static readonly JavaScriptSerializer Json=new JavaScriptSerializer();

    public static Session Active;

    public static string Quote(string s) { return "\""+s.Replace("\"","\\\"")+"\""; }

    static string Digest(string path) {

        using(var sha=SHA256.Create()) using(var input=File.OpenRead(path))

            return BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();

    }

    static void Save(Session s) {

        string temp=State+".tmp";

        File.WriteAllText(temp,Json.Serialize(s),new UTF8Encoding(false));

        if(File.Exists(State)) File.Replace(temp,State,null); else File.Move(temp,State);

    }

    public static void Audit(string action,object detail) {

        Directory.CreateDirectory(Path.Combine(Root,"logs"));

        File.AppendAllText(Path.Combine(Root,"logs","controller.jsonl"),

            Json.Serialize(new {time=DateTime.UtcNow.ToString("o"),action=action,detail=detail})+Environment.NewLine,new UTF8Encoding(false));

    }

    static void Network(string mode,params string[] files) {

        var p=new Process();p.StartInfo=new ProcessStartInfo(Path.Combine(Root,"CycloneNetwork.exe"),mode+" "+String.Join(" ",Array.ConvertAll(files,Quote)));

        p.StartInfo.UseShellExecute=false;p.StartInfo.CreateNoWindow=true;p.StartInfo.RedirectStandardOutput=true;p.StartInfo.RedirectStandardError=true;

        p.Start();string output=p.StandardOutput.ReadToEnd(),error=p.StandardError.ReadToEnd();

        if(!p.WaitForExit(15000)) {p.Kill();throw new Exception("Network rule operation timed out");}

        if(p.ExitCode!=0) throw new Exception("Network rule "+mode+": "+error+output);

        Audit("network-"+mode,output.Trim());p.Dispose();

    }

    static bool Alive(Session s) {

        try { using(var p=Process.GetProcessById(s.pid)) return !p.HasExited && p.StartTime.ToFileTimeUtc().ToString()==s.startedFileTime; }

        catch {return false;}

    }

    public static void Recover() {

        if(!File.Exists(State)) return;

        var old=Json.Deserialize<Session>(File.ReadAllText(State));

        if(Alive(old)) throw new Exception("已有接管会话运行，请先关闭原窗口。");

        Restore(old);

        Audit("recovered-stale-session",old.engine);

    }

    static void Restore(Session s) {

        string expectedParent=Ifeo+"\\cyclone-nn-opt.exe";

        if(s.parent!=expectedParent || s.filter==null || !s.filter.StartsWith("CycloneOffline_",StringComparison.Ordinal)) throw new Exception("Session restoration record is invalid");

        Guid token=Guid.Parse(s.session);

        File.Delete(Path.Combine(Root,"session-"+token.ToString()+".active"));

        using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))

        using(var parent=machine.OpenSubKey(s.parent,true)) {

            if(parent!=null) {

                using(var filter=parent.OpenSubKey(s.filter)) {

                    if(filter!=null && (!String.Equals((string)filter.GetValue("FilterFullPath"),s.engine,StringComparison.OrdinalIgnoreCase) ||

                        (string)filter.GetValue("Debugger")!=s.debugger)) throw new Exception("启动规则已被其他操作修改；保留现状以免覆盖。");

                }

                parent.DeleteSubKeyTree(s.filter,false);

                // Restore the switch only when no other filter depends on it.

                if(parent.SubKeyCount==0 && Object.Equals(parent.GetValue("UseFilter"),1)) {

                    if(s.hadUseFilter) parent.SetValue("UseFilter",s.oldUseFilter,RegistryValueKind.DWord);

                    else parent.DeleteValue("UseFilter",false);

                }

            }

        }

        using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))

        using(var top=machine.OpenSubKey(Ifeo,true)) {

            bool empty=false;

            using(var parent=top.OpenSubKey("cyclone-nn-opt.exe")) if(parent!=null) empty=parent.ValueCount==0 && parent.SubKeyCount==0;

            if(empty) top.DeleteSubKey("cyclone-nn-opt.exe",false);

        }

        File.Delete(State);

        Audit("restored-launch-rule",new {engine=s.engine,network="Block rules retained"});

    }

    public static void Stop() {

        if(Active==null) return;

        Restore(Active);Active=null;

    }

    public static void Start(string path) {

        if(Active!=null) throw new Exception("请先停止当前接管。");

        Recover();

        string engine=Path.GetFullPath(path);

        if(!String.Equals(Path.GetFileName(engine),"cyclone-nn-opt.exe",StringComparison.OrdinalIgnoreCase)) throw new Exception("请选择 cyclone-nn-opt.exe 原引擎。");

        if(!File.Exists(engine) || Digest(engine)!=Expected) throw new Exception("原引擎版本不匹配：SHA256 校验失败。");

        if(!File.Exists(Path.Combine(Path.GetDirectoryName(engine),"cyclone-eval.nnue"))) throw new Exception("原引擎目录缺少 cyclone-eval.nnue。");

        string hook=Path.Combine(Root,"CycloneHook.exe"),helper=Path.Combine(Root,"CycloneNetwork.exe");

        if(!File.Exists(hook) || !File.Exists(helper)) throw new Exception("请完整解压辅助程序文件夹。");

        var s=new Session {engine=engine,session=Guid.NewGuid().ToString(),pid=Process.GetCurrentProcess().Id,

            startedFileTime=Process.GetCurrentProcess().StartTime.ToFileTimeUtc().ToString(),parent=Ifeo+"\\cyclone-nn-opt.exe",

            debugger=Quote(hook)+" --ifeo"};

        using(var sha=SHA256.Create()) s.filter="CycloneOffline_"+BitConverter.ToString(sha.ComputeHash(Encoding.Unicode.GetBytes(engine.ToLowerInvariant()))).Replace("-","").Substring(0,16);

        s.marker=Path.Combine(Root,"session-"+s.session+".active");

        using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))

        using(var parent=machine.OpenSubKey(s.parent)) {

            if(parent!=null) {

                if(parent.GetValue("Debugger")!=null) throw new Exception("已有全局调试启动规则，请先处理现有规则。");

                object current=parent.GetValue("UseFilter");

                if(current!=null && !(current is int)) throw new Exception("已有 UseFilter 类型不兼容。");

                s.hadUseFilter=current!=null;s.oldUseFilter=current==null?0:(int)current;

                if(parent.SubKeyCount>0 && !Object.Equals(current,1)) throw new Exception("已有未启用的路径过滤规则；为保持现状，本助手未启动接管。");

                foreach(string name in parent.GetSubKeyNames()) using(var key=parent.OpenSubKey(name))

                    if(String.Equals(key.GetValue("FilterFullPath") as string,engine,StringComparison.OrdinalIgnoreCase))

                        throw new Exception("所选路径已有启动过滤规则，请先恢复该规则。");

            }

        }

        Network("install",hook,engine,helper);

        Network("verify",hook,engine,helper);

        Save(s);Active=s;

        try {

            File.WriteAllText(s.marker,s.session);

            using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))

            using(var parent=machine.CreateSubKey(s.parent)) {

                using(var filter=parent.CreateSubKey(s.filter)) {

                    filter.SetValue("FilterFullPath",engine,RegistryValueKind.String);

                    filter.SetValue("Debugger",s.debugger,RegistryValueKind.String);

                }

                parent.SetValue("UseFilter",1,RegistryValueKind.DWord);

            }

            Audit("active",s);

        } catch {Stop();throw;}

    }

}





}

