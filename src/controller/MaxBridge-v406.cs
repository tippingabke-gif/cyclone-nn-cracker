using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
static class MaxBridge {
 static int Main(string[] args) {
  NamedPipeClientStream input=null,outputPipe=null;
  try {
   string root=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
   var json=new JavaScriptSerializer();var state=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(root,"active-session.json")));
   string engine=state["engine"].ToString(),token=state["session"].ToString(),marker=state["marker"].ToString();
   if(args.Length!=2||args[0]!="--ifeo"||!String.Equals(Path.GetFullPath(args[1]),engine,StringComparison.OrdinalIgnoreCase)||!File.Exists(marker))throw new Exception("请先启动三版本助手。");
   using(var owner=Process.GetProcessById(Convert.ToInt32(state["pid"])))if(owner.HasExited||owner.StartTime.ToFileTimeUtc().ToString()!=state["startedFileTime"].ToString())throw new Exception("助手会话已结束。");
   string logs=Path.Combine(root,"logs",token),prefix;
   var service=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(logs,"max-summary.json")));
   using(var live=Process.GetProcessById(Convert.ToInt32(service["servicePid"])))if(live.HasExited)throw new Exception("MAX 服务已结束。");
   using(var hash=SHA256.Create())prefix="CycloneMAX-v406-"+BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(engine.ToLowerInvariant()))).Replace("-","").Substring(0,16).ToLowerInvariant();
   string line;
   while((line=Console.ReadLine())!=null){
    if(input==null){
     if(line.Trim()=="quit")break;
     if(line.Trim()=="uci"){
      // Registration reads the real engine's captured identification response
      // without occupying the sole calculation channel.
      foreach(string item in File.ReadAllLines(Path.Combine(logs,"uci-cache.txt")))Console.WriteLine(item);
      Console.Out.Flush();continue;
     }
     input=new NamedPipeClientStream(".",prefix+"-in",PipeDirection.Out);
     outputPipe=new NamedPipeClientStream(".",prefix+"-out",PipeDirection.In);
     input.Connect(12000);outputPipe.Connect(12000);
     var output=Console.OpenStandardOutput();var pipe=outputPipe;
     var reader=new Thread(()=>{try{var b=new byte[8192];int n;while((n=pipe.Read(b,0,b.Length))>0){output.Write(b,0,n);output.Flush();}}catch(IOException){}catch(ObjectDisposedException){}});
     reader.IsBackground=true;reader.Start();
    }
    byte[] bytes=Encoding.UTF8.GetBytes(line+"\n");input.Write(bytes,0,bytes.Length);input.Flush();if(line.Trim()=="quit")break;
   }
   return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex.Message);return 1;}
  finally{if(input!=null)input.Dispose();if(outputPipe!=null)outputPipe.Dispose();}
 }
}
