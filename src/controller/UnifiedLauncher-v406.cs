using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("旋风三版本加载助手")]
[assembly: AssemblyProduct("Cyclone Unified Helper")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyCopyright("")]
[assembly: AssemblyVersion("4.0.6.0")]

sealed class EngineRow {
 public string Kind,Name;public Label State;public TextBox PathBox;public Button Start,Stop;public bool Active,Busy;
}
sealed class UnifiedForm:Form {
 readonly List<EngineRow> rows=new List<EngineRow>();bool closing;
 public UnifiedForm() {
  Text="旋风三版本加载助手";ClientSize=new Size(790,480);Font=new Font("Microsoft YaHei UI",9.5f);
  FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;StartPosition=FormStartPosition.CenterScreen;
  Controls.Add(new Label{Text="旋风 OPT · COM · MAX",Font=new Font(Font.FontFamily,20,FontStyle.Bold),Left=24,Top=20,Width=690,Height=42});
  Controls.Add(new Label{Text="放在三个原引擎所在文件夹，启用需要的版本，再在棋盘中加载原 EXE。",Left=26,Top=70,Width=735,Height=28});
  AddRow("OPT","cyclone-nn-opt.exe",110);AddRow("COM","cyclone-nn-com.exe",202);AddRow("MAX","cyclone-nn-opt-max.exe",294);
  Controls.Add(new Label{Text="虚拟机加载与计算测试通过",Left=26,Top=397,Width=350,Height=25,ForeColor=Color.DimGray});
  var mark=new LinkLabel{Text="github.com/tippingabke-gif",Left=26,Top=434,Width=450,Height=26,Font=new Font(Font.FontFamily,11,FontStyle.Bold),LinkColor=Color.SteelBlue};
  mark.LinkClicked+=(o,e)=>Process.Start(new ProcessStartInfo("https://github.com/tippingabke-gif"){UseShellExecute=true});Controls.Add(mark);
  Controls.Add(new Label{Text="UCI · 保持助手运行",Left=570,Top=435,Width=195,Height=24,TextAlign=ContentAlignment.MiddleRight,ForeColor=Color.DimGray});
  FormClosing+=async(o,e)=>{
   if(closing)return;
   if(rows.Exists(r=>r.Busy)){e.Cancel=true;MessageBox.Show(this,"正在准备引擎，请等当前操作完成。","加载助手");return;}
   if(!rows.Exists(r=>r.Active))return;
   e.Cancel=true;Enabled=false;
   try {await Task.Run(()=>UnifiedProgram.StopAll());closing=true;Close();}
   catch(Exception ex){Enabled=true;MessageBox.Show(this,ex.Message,"停止结果");}
  };
 }
 void AddRow(string kind,string name,int y) {
  var row=new EngineRow{Kind=kind,Name=name};rows.Add(row);
  Controls.Add(new Label{Text=kind,Left=26,Top=y+3,Width=50,Height=24,Font=new Font(Font,FontStyle.Bold)});
  row.PathBox=new TextBox{Text=Path.Combine(UnifiedProgram.Root,name),Left=82,Top=y,Width=475,ReadOnly=true};Controls.Add(row.PathBox);
  row.Start=new Button{Text="启用",Left=570,Top=y-2,Width=85,Height=31};Controls.Add(row.Start);
  row.Stop=new Button{Text="停止",Left=667,Top=y-2,Width=85,Height=31,Enabled=false};Controls.Add(row.Stop);
  row.State=new Label{Text=File.Exists(row.PathBox.Text)?"已找到原引擎，等待启用":"未找到 "+name,Left=82,Top=y+34,Width=670,Height=40,ForeColor=Color.DimGray};Controls.Add(row.State);
  row.Start.Enabled=File.Exists(row.PathBox.Text);
  row.Start.Click+=async(o,e)=>{
   row.Busy=true;row.Start.Enabled=false;row.State.Text="正在核验并准备引擎，请稍候……";row.State.ForeColor=Color.DimGray;
   try {await Task.Run(()=>UnifiedProgram.Start(row.Kind,row.PathBox.Text));row.Active=true;row.Stop.Enabled=true;row.State.Text="已启用。在棋盘中加载上方原文件，协议选择 UCI。";row.State.ForeColor=Color.DarkGreen;}
   catch(Exception ex){row.State.Text=ex.Message;row.State.ForeColor=Color.Firebrick;row.Start.Enabled=true;}
   finally{row.Busy=false;}
  };
  row.Stop.Click+=async(o,e)=>{
   row.Busy=true;row.Stop.Enabled=false;
   try {await Task.Run(()=>UnifiedProgram.Stop(row.Kind));row.Active=false;row.Start.Enabled=true;row.State.Text="已停止，启动接管已恢复。";row.State.ForeColor=Color.DimGray;}
   catch(Exception ex){row.State.Text=ex.Message;row.State.ForeColor=Color.Firebrick;row.Stop.Enabled=true;}
   finally{row.Busy=false;}
  };
 }
}
static class UnifiedProgram {
 public static readonly string Root=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
 public static void Start(string kind,string engine) {
  if(kind=="OPT"){BackendOPT.RuntimeBundle.Ensure();BackendOPT.Controller.Recover();BackendOPT.Controller.Start(engine);}
  else if(kind=="COM"){BackendCOM.RuntimeBundle.Ensure();BackendCOM.Controller.Recover();BackendCOM.Controller.Start(engine);}
  else if(kind=="MAX"){BackendMAX.RuntimeBundle.Ensure();BackendMAX.Controller.Recover();BackendMAX.Controller.Start(engine);}
  else throw new ArgumentException("Unknown variant");
 }
 public static void Stop(string kind){if(kind=="OPT")BackendOPT.Controller.Stop();else if(kind=="COM")BackendCOM.Controller.Stop();else if(kind=="MAX")BackendMAX.Controller.Stop();}
 public static void StopAll(){Stop("MAX");Stop("COM");Stop("OPT");}
 [STAThread] public static int Main(string[] args) {
  bool owned;using(var mutex=new Mutex(true,"Global\\CycloneUnifiedHelperV406",out owned)){
   if(!owned){MessageBox.Show("已有三版本助手正在运行。");return 2;}
   try {
    if(args.Length==4&&args[0]=="--headless"){
     string kind=args[1],stop=Path.GetFullPath(args[3]);if(File.Exists(stop))throw new Exception("Stop marker already exists");
     Start(kind,Path.GetFullPath(args[2]));try{while(!File.Exists(stop))Thread.Sleep(100);}finally{Stop(kind);}return 0;
    }
    if(args.Length==1&&args[0]=="--prepare"){BackendOPT.RuntimeBundle.Ensure();BackendCOM.RuntimeBundle.Ensure();BackendMAX.RuntimeBundle.Ensure();return 0;}
    Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new UnifiedForm());return 0;
   }catch(Exception ex){File.WriteAllText(Path.Combine(Root,"helper-error.txt"),ex.ToString());if(args.Length==0)MessageBox.Show(ex.Message,"加载助手");return 1;}
   finally{StopAll();mutex.ReleaseMutex();}
  }
 }
}
