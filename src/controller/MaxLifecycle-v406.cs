using System;

using System.Collections.Generic;

using System.Diagnostics;

using System.IO;

using System.Security.Cryptography;

using System.Text;

using System.Threading;

using System.Web.Script.Serialization;

using System.Runtime.InteropServices;

namespace BackendMAX {

 public static class MaxLifecycle {

  static Process worker;static string logRoot;

  static string aliasRoot;static bool ownsAlias;

  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);

  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(IntPtr h,uint code,byte[] input,uint length,IntPtr output,uint outputLength,out uint returned,IntPtr overlapped);

  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr h,StringBuilder path,uint length,uint flags);

  static string FinalDirectory(string path) {

   IntPtr h=CreateFile(path,0,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);if(h==new IntPtr(-1))throw new System.ComponentModel.Win32Exception();

   try{var b=new StringBuilder(32768);if(GetFinalPathNameByHandle(h,b,(uint)b.Capacity,0)==0)throw new System.ComponentModel.Win32Exception();return b.ToString().Replace(@"\\?\","").TrimEnd('\\');}finally{CloseHandle(h);}

  }

  static void PrepareAlias(string engine) {

   string target=Path.GetFullPath(Path.GetDirectoryName(engine));string digest;

   using(var h=SHA256.Create())digest=BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(target.ToLowerInvariant()))).Replace("-","").Substring(0,20);

   string parent=Path.Combine(Path.GetPathRoot(target),"CycloneHelperPaths-v406");Directory.CreateDirectory(parent);aliasRoot=Path.Combine(parent,digest);

   if(Directory.Exists(aliasRoot)){

    if((File.GetAttributes(aliasRoot)&FileAttributes.ReparsePoint)==0||!String.Equals(FinalDirectory(aliasRoot),target,StringComparison.OrdinalIgnoreCase))throw new Exception("内部路径映射已被其他目录占用。");

    return;

   }

   Directory.CreateDirectory(aliasRoot);ownsAlias=true;

   byte[] substitute=Encoding.Unicode.GetBytes(@"\??\"+target),print=Encoding.Unicode.GetBytes(target);

   byte[] data=new byte[16+substitute.Length+2+print.Length+2];

   Array.Copy(BitConverter.GetBytes(0xA0000003u),0,data,0,4);Array.Copy(BitConverter.GetBytes((ushort)(data.Length-8)),0,data,4,2);

   Array.Copy(BitConverter.GetBytes((ushort)substitute.Length),0,data,10,2);Array.Copy(BitConverter.GetBytes((ushort)(substitute.Length+2)),0,data,12,2);Array.Copy(BitConverter.GetBytes((ushort)print.Length),0,data,14,2);

   Array.Copy(substitute,0,data,16,substitute.Length);Array.Copy(print,0,data,18+substitute.Length,print.Length);

   IntPtr handle=CreateFile(aliasRoot,0x40000000,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero);

   if(handle==new IntPtr(-1))throw new System.ComponentModel.Win32Exception();

   try{uint returned;if(!DeviceIoControl(handle,0x900A4,data,(uint)data.Length,IntPtr.Zero,0,out returned,IntPtr.Zero))throw new System.ComponentModel.Win32Exception();}finally{CloseHandle(handle);}

   if(!String.Equals(FinalDirectory(aliasRoot),target,StringComparison.OrdinalIgnoreCase))throw new Exception("内部路径映射校验失败。");

  }

  static void RemoveAlias(){if(ownsAlias&&aliasRoot!=null&&Directory.Exists(aliasRoot)){Directory.Delete(aliasRoot);ownsAlias=false;}}

  static readonly JavaScriptSerializer Json=new JavaScriptSerializer();

  static string Hash(string path){using(var h=SHA256.Create())using(var s=File.OpenRead(path))return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant();}

  public static void InstallNetwork(string engine) {

   PrepareAlias(engine);

   string helper=Path.Combine(Controller.Root,"CycloneNetwork.exe");

   var programs=new[]{Path.Combine(aliasRoot,Path.GetFileName(engine)),Path.Combine(aliasRoot,Path.GetFileName(Controller.Root),"SDE","sde.exe"),Path.Combine(aliasRoot,Path.GetFileName(Controller.Root),"SDE","pin.exe"),engine,Path.Combine(Controller.Root,"CycloneMaxBridge.exe"),Path.Combine(Controller.Root,"CycloneMaxWorker.exe"),Path.Combine(Controller.Root,"SDE","sde.exe"),Path.Combine(Controller.Root,"SDE","pin.exe"),helper};

   File.WriteAllText(Path.Combine(Controller.Root,"network-programs.json"),Json.Serialize(programs));

   foreach(string mode in new[]{"install","verify"}) {

    using(var p=Process.Start(new ProcessStartInfo(helper,mode+" "+String.Join(" ",Array.ConvertAll(programs,Controller.Quote))){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true})) {

     string output=p.StandardOutput.ReadToEnd(),error=p.StandardError.ReadToEnd();

     if(!p.WaitForExit(15000)){p.Kill();throw new Exception("Network rule operation timed out");}

     if(p.ExitCode!=0)throw new Exception("Network "+mode+": "+error+output);

    }

   }

  }

  public static void Start(Session s) {

   string model=Path.Combine(Path.GetDirectoryName(s.engine),"cyclone-eval.nnue");

   if(Hash(model)!="324d1fb215d5dacb1278da0820ce79b8cbadca2c0fce01f1d3c83bb04459709d")throw new Exception("NNUE 模型版本不匹配。");

   if(aliasRoot==null)PrepareAlias(s.engine);

   logRoot=Path.Combine(Controller.Root,"logs",s.session);Directory.CreateDirectory(logRoot);

   var info=new ProcessStartInfo(Path.Combine(Controller.Root,"CycloneMaxWorker.exe"));

   info.UseShellExecute=false;info.CreateNoWindow=true;info.WorkingDirectory=Path.GetDirectoryName(s.engine);

   info.EnvironmentVariables["CYCLONE_MAX_ENGINE"]=s.engine;

   info.EnvironmentVariables["CYCLONE_MAX_OUTPUT"]=logRoot;

   info.EnvironmentVariables["CYCLONE_MAX_MARKER"]=s.marker;

   info.EnvironmentVariables["CYCLONE_MAX_OWNER"]=s.pid.ToString();

   info.EnvironmentVariables["CYCLONE_MAX_SDE"]=Path.Combine(aliasRoot,Path.GetFileName(Controller.Root),"SDE","sde.exe");

   info.EnvironmentVariables["CYCLONE_MAX_LAUNCH_ENGINE"]=Path.Combine(aliasRoot,Path.GetFileName(s.engine));

   string pipe;using(var hash=SHA256.Create())pipe=BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(s.engine.ToLowerInvariant()))).Replace("-","").Substring(0,16).ToLowerInvariant();

   info.EnvironmentVariables["CYCLONE_MAX_PIPE"]="CycloneMAX-v406-"+pipe;

   worker=Process.Start(info);var deadline=DateTime.UtcNow.AddMinutes(5);

   while(DateTime.UtcNow<deadline){

    if(worker.HasExited)throw new Exception("MAX 准备失败，请查看助手日志。");

    try {var state=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(logRoot,"max-summary.json")));string status=state["status"].ToString();if(status=="ready-for-board")return;if(status=="error")throw new InvalidOperationException("MAX 准备失败，请查看助手日志。");}

    catch(IOException){}catch(ArgumentException){}

    Thread.Sleep(200);

   }

   throw new Exception("MAX 准备超时，请查看助手日志。");

  }

  public static void Stop() {

   if(worker==null){RemoveAlias();return;}

   try {

    if(!worker.HasExited){

     if(logRoot!=null)File.WriteAllText(Path.Combine(logRoot,"stop.flag"),"controller stopped");

     if(!worker.WaitForExit(20000)){

      using(var kill=Process.Start(new ProcessStartInfo("taskkill.exe","/PID "+worker.Id+" /T /F"){UseShellExecute=false,CreateNoWindow=true}))kill.WaitForExit(10000);

     }

    }

   }finally{worker.Dispose();worker=null;RemoveAlias();}

  }

 }

}

