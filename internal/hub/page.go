package hub

import (
	"fmt"
	"net/http"
)

func (h *AdminHandler) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminPageHTML)
}

const adminPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>oc-link 中继</title>
<style>
  :root{--bg:#f4f6fb;--panel:#ffffff;--panel2:#eef1f8;--line:#e0e5f0;--text:#1a1f2e;--muted:#67708a;--accent:#3b6fe0;--ok:#1f9d5b;--warn:#c07b1a;--err:#d64545;--radius:12px}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
  .wrap{max-width:980px;margin:0 auto;padding:22px 18px 40px}
  header{display:flex;align-items:center;gap:12px;margin-bottom:18px}
  .logo{width:30px;height:30px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;color:#fff;background:linear-gradient(135deg,#5b8cff,#7c5cff)}
  h1{font-size:17px;margin:0}.sub{color:var(--muted);font-size:12px}
  .spacer{flex:1}
  button{border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:8px;padding:6px 12px;font-size:13px;cursor:pointer}
  button:hover{filter:brightness(1.15)}button:disabled{opacity:.45;cursor:default}
  button.primary{background:linear-gradient(135deg,#5b8cff,#7c5cff);border:0;color:#fff;font-weight:600}
  button.danger{color:var(--err);border-color:#5a2a2a;background:transparent}
  button.ghost{background:transparent}
  input{width:100%;border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:8px;padding:9px 12px;font:inherit}
  .tabs{display:flex;gap:6px;margin-bottom:14px}
  .tab{padding:7px 16px;border-radius:9px;background:var(--panel);border:1px solid var(--line);color:var(--muted);cursor:pointer;font-size:13px}
  .tab.active{color:var(--text);border-color:var(--accent);background:var(--panel2);font-weight:600}
  .grid{display:flex;flex-direction:column;gap:10px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px}
  .dev-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .name{font-weight:700;font-size:15px}
  .pills{display:flex;gap:6px;margin-left:auto}
  .pill{font-size:11.5px;border-radius:999px;padding:2px 10px;border:1px solid var(--line);color:var(--muted)}
  .pill.on{color:var(--ok);border-color:#1f5c3a}  .pill.busy{color:var(--accent);border-color:#2a4a8a}.pill.off{color:var(--muted)}
  .pill.err{color:var(--err);border-color:color-mix(in srgb,var(--err) 45%,var(--line))}
  /* —— 卡片视觉：被控端=蓝 / 控制端=青，在线带光 —— */
  .card{position:relative;overflow:hidden;transition:box-shadow .25s,border-color .25s,transform .25s}
  .card:hover{transform:translateY(-1px);box-shadow:0 14px 34px rgba(30,40,70,.12)}
  .card.dev{border-left:3px solid #5b8cff}
  .card.cli{border-left:3px solid #12b3a8}
  .card.dev.on{box-shadow:0 10px 28px rgba(91,140,255,.14);border-color:color-mix(in srgb,#5b8cff 30%,var(--line))}
  .card.cli.on{box-shadow:0 10px 28px rgba(18,179,168,.16);border-color:color-mix(in srgb,#12b3a8 32%,var(--line))}
  .card.on .name{font-size:16px}
  .pill{display:inline-flex;align-items:center;gap:5px;background:var(--panel2)}
  .pill::before{content:'';width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.45}
  .pill.on{background:color-mix(in srgb,var(--ok) 12%,var(--panel));border-color:color-mix(in srgb,var(--ok) 40%,var(--line))}
  .pill.on::before{background:var(--ok);opacity:1;box-shadow:0 0 7px var(--ok);animation:dotpulse 1.8s ease-in-out infinite}
  .pill.busy{background:color-mix(in srgb,var(--accent) 11%,var(--panel));border-color:color-mix(in srgb,var(--accent) 38%,var(--line))}
  .pill.busy::before{background:var(--accent);opacity:1;box-shadow:0 0 7px var(--accent);animation:dotpulse 1.8s ease-in-out infinite}
  .pill.err{background:color-mix(in srgb,var(--err) 10%,var(--panel))}
  .pill.err::before{background:var(--err);opacity:1}
  .pill.warn{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 42%,var(--line));background:color-mix(in srgb,var(--warn) 10%,var(--panel))}
  .pill.warn::before{background:var(--warn);opacity:1;animation:dotpulse 1.8s ease-in-out infinite}
  .card.cli .pill.busy{color:#0e9a92;border-color:color-mix(in srgb,#12b3a8 45%,var(--line));background:color-mix(in srgb,#12b3a8 11%,var(--panel))}
  .card.cli .pill.busy::before{background:#12b3a8;box-shadow:0 0 7px #12b3a8}
  @keyframes dotpulse{50%{opacity:.3}}
  .tab.active{color:#fff;border-color:transparent;background:linear-gradient(135deg,#5b8cff,#7c5cff);box-shadow:0 4px 12px rgba(91,140,255,.25)}
  /* —— 操作按钮：断裂占用=素雅白，禁用=软红（悬停实心红） —— */
  .actions button{border-radius:10px;padding:8px 16px;font-size:12.5px;font-weight:600;border:1px solid var(--line);background:linear-gradient(180deg,#fff,#f3f6fc);color:#2c3550;box-shadow:0 1px 2px rgba(30,40,70,.05);transition:all .18s ease}
  .actions button:hover{filter:none;border-color:#c9d4ec;background:linear-gradient(180deg,#fff,#eaf0fb);box-shadow:0 4px 12px rgba(30,40,70,.10);transform:translateY(-1px)}
  .actions button:active{transform:none;box-shadow:none}
  .actions button:disabled{opacity:.45;box-shadow:none;transform:none;cursor:default}
  button.danger{color:#d43d3d;border-color:color-mix(in srgb,var(--err) 35%,var(--line));background:color-mix(in srgb,var(--err) 7%,#fff)}
  button.danger:hover{filter:none;background:linear-gradient(135deg,#e05252,#c73c3c);color:#fff;border-color:transparent;box-shadow:0 6px 16px rgba(214,69,69,.30)}
  .meta{color:var(--muted);font-size:12px;margin-top:6px;word-break:break-all}
  .meta code{color:var(--text);background:var(--panel2);border-radius:4px;padding:0 5px}
  .actions{display:flex;gap:8px;margin-top:10px}
  .section{font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.5px;margin:4px 2px -2px}
  .rel{display:flex;align-items:center;gap:8px;padding:9px 0;border-bottom:1px dashed var(--line);flex-wrap:wrap}
  .rel:last-child{border-bottom:0}
  .rel .from,.rel .to{font-weight:700;font-size:13.5px}
  .rel .arrow{color:var(--muted);font-size:13px}
  .rel .when{color:var(--muted);font-size:12px}
  .rel .flex1{flex:1;min-width:0}
  .rel code{color:var(--text);background:var(--panel2);border-radius:4px;padding:0 5px;font-size:11.5px}
  .ctrl{margin-top:9px;background:var(--panel2);border-radius:9px;padding:8px 10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .ctrl .who{font-weight:700}
  .ctrl .when{color:var(--muted);font-size:12px}
  .ctrl .flex1{flex:1;min-width:0}
  .empty{color:var(--muted);text-align:center;padding:30px 0}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px dashed var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:500}
  td.mono{font-variant-numeric:tabular-nums;color:var(--muted);white-space:nowrap}
  .login{max-width:360px;margin:12vh auto;text-align:center}
  .login .logo{width:44px;height:44px;border-radius:12px;font-size:15px;margin:0 auto 12px}
  .toast{position:fixed;right:18px;bottom:18px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:9px 14px;font-size:13px;display:none}
  .toast.show{display:block}
  .hidden{display:none!important}
  .modal{position:fixed;inset:0;background:rgba(20,25,40,.35);display:flex;align-items:center;justify-content:center;z-index:300}
  .modal-box{width:min(430px,90vw);background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:0 12px 40px rgba(30,40,70,.18);padding:18px 18px 14px}
  .modal-title{font-weight:700;font-size:15px;margin-bottom:8px}
  .modal-text{font-size:13.5px;line-height:1.65;white-space:pre-line}
  .modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
  .modal.danger #modalOk{background:var(--err);border:0;color:#fff;font-weight:600}
</style>
</head>
<body>
<div class="wrap hidden" id="loginView">
  <div class="login">
    <div class="logo">ol</div>
    <h1>oc-link 中继</h1>
    <div style="margin-top:14px"><input id="uname" placeholder="账号" value="admin" autofocus></div>
    <div style="margin-top:10px"><input id="pw" type="password" placeholder="密码"></div>
    <div style="margin-top:10px"><button class="primary" style="width:100%" onclick="doLogin()">登录</button></div>
    <p class="sub" id="loginErr" style="color:var(--err);margin-top:10px"></p>
  </div>
</div>

<div class="wrap" id="bootView">
  <div class="login">
    <div class="logo">ol</div>
    <h1>oc-link 中继</h1>
    <p class="sub" style="margin-top:12px">正在加载…</p>
  </div>
</div>

<div class="wrap hidden" id="mainView">
  <header>
    <div class="logo">ol</div>
    <div>
      <h1>oc-link 中继</h1>
      <div class="sub" id="summary">加载中…</div>
    </div>
    <div class="spacer"></div>
    <button class="ghost" onclick="manualRefresh()">刷新</button>
    <button class="ghost" onclick="doLogout()">退出</button>
  </header>
  <div class="tabs">
    <div class="tab active" id="tab-devices" onclick="showTab('devices')">被控端</div>
    <div class="tab" id="tab-clients" onclick="showTab('clients')">控制端</div>
    <div class="tab" id="tab-audit" onclick="showTab('audit')">审计</div>
  </div>
  <div id="devicesView"><div class="grid" id="deviceGrid"></div></div>
  <div id="clientsView" class="hidden"><div class="grid" id="clientGrid"></div></div>
  <div id="auditView" class="hidden"><div class="card"><div class="sub" id="auditCount" style="margin-bottom:8px"></div><table><thead><tr><th>时间</th><th>动作</th><th>设备</th><th>说明</th></tr></thead><tbody id="auditBody"></tbody></table><div style="text-align:center;margin-top:12px"><button id="btnMoreAudit" onclick="moreAudit()">加载更多</button></div></div></div>
</div>
<div class="toast" id="toast"></div>
<div class="modal hidden" id="modalRoot">
  <div class="modal-box">
    <div class="modal-title" id="modalTitle">确认</div>
    <div class="modal-text" id="modalText"></div>
    <div class="modal-actions">
      <button id="modalCancel" style="background:transparent">取消</button>
      <button class="primary" id="modalOk">确定</button>
    </div>
  </div>
</div>

<script>
var $=function(id){return document.getElementById(id)};
var me=null,tab="devices",timer=null;
var keepAlive={},keepDev={}; // 刚操作过（启用/允许重连）的对象：保留卡片显示「等待重连…」，避免闪没
function toast(msg){var t=$('toast');t.textContent=msg;t.className='toast show';setTimeout(function(){t.className='toast'},2200)}
function confirmDialog(opts){return new Promise(function(resolve){var root=$('modalRoot');$('modalTitle').textContent=opts.title||'确认';$('modalText').textContent=opts.message||'';$('modalOk').textContent=opts.okText||'确定';root.className='modal'+(opts.danger?' danger':'');var done=function(v){root.className='modal hidden';$('modalOk').onclick=null;$('modalCancel').onclick=null;root.onclick=null;resolve(v)};$('modalOk').onclick=function(){done(true)};$('modalCancel').onclick=function(){done(false)};root.onclick=function(ev){if(ev.target===root)done(false)}})}
async function api(path,opt){opt=opt||{};opt.credentials='same-origin';if(opt.body)opt.headers={'Content-Type':'application/json'};var r=await fetch(path,opt);if(r.status===401){showLogin();throw new Error('unauthorized')}return r.json()}
async function doLogin(){try{$('loginErr').textContent='';var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('uname').value,password:$('pw').value})});if(!r.ok){var j=null;try{j=await r.json()}catch(e2){}throw new Error((j&&j.error)||'账号或密码错误')}$('pw').value='';showMain();await refresh()}catch(e){$('loginErr').textContent=e.message}}
async function doLogout(){try{await api('/api/logout',{method:'POST'})}catch(e){}showLogin()}
function showLogin(){$('bootView').classList.add('hidden');$('loginView').classList.remove('hidden');$('mainView').classList.add('hidden')}
function showMain(){$('bootView').classList.add('hidden');$('loginView').classList.add('hidden');$('mainView').classList.remove('hidden')}
function showTab(t){tab=t;['devices','audit','clients'].forEach(function(id){var on=id===t;document.getElementById('tab-'+id).className='tab'+(on?' active':'');document.getElementById(id+'View').className=on?'':'hidden'});if(t==='audit')auditNeedReload=true;refresh()}
function fmtAgo(ts){if(!ts)return '-';var d=Date.now()-new Date(ts).getTime();if(d<60000)return '刚刚';if(d<3600000)return Math.floor(d/60000)+' 分钟前';if(d<86400000)return Math.floor(d/3600000)+' 小时前';return new Date(ts).toLocaleDateString('zh-CN')}
function fmtTime(ts){if(!ts)return '-';return new Date(ts).toLocaleString('zh-CN',{hour12:false})}
function fmtLeft(ts){var ms=new Date(ts).getTime()-Date.now();if(ms<=0)return '0:00';var s=Math.floor(ms/1000);var m=Math.floor(s/60);s=s%60;return m+':'+(s<10?'0':'')+s}
async function refresh(){try{
  if(tab==='devices'){
    var d=await api('/api/devices');var all=d.devices||[];
    // 只显示在线的（离线设备不占卡片）；被禁用的保留显示，便于启用
    var list=all.filter(function(x){return x.agentOnline||x.clientOnline});
    var online=all.filter(function(x){return x.agentOnline}).length;
    $('summary').textContent=online+' 台在线'+(all.length>list.length?(' · 另有 '+(all.length-list.length)+' 台离线'):'');
    var g=$('deviceGrid');g.innerHTML='';
    if(!list.length&&!all.length){g.innerHTML='<div class="card empty">还没有任何设备。B 端「生成邀请码」并接入后会出现在这里。</div>';return}
    list.forEach(function(x){
      var c=document.createElement('div');c.className='card dev'+(x.agentOnline?' on':'');
      var h=document.createElement('div');h.className='dev-head';
      var n=document.createElement('div');n.className='name';n.textContent=x.name;h.appendChild(n);
      var p=document.createElement('div');p.className='pills';
      var pillB=document.createElement('span');pillB.className='pill '+(x.agentOnline?'on':'off');pillB.textContent=x.agentOnline?'B 在线':'B 离线';p.appendChild(pillB);
      var cooling=x.cooldownUntil&&(new Date(x.cooldownUntil).getTime()>Date.now());
      var pillC=document.createElement('span');
      if(cooling){pillC.className='pill warn';pillC.textContent='已断开 · 冷却 '+fmtLeft(x.cooldownUntil)}
      else if(x.clientOnline&&!x.agentOnline){pillC.className='pill warn';pillC.textContent='等待被控端 · '+(x.clientName||'未命名')}
      else{pillC.className='pill '+(x.clientOnline?'busy':'off');pillC.textContent=x.clientOnline?('控制中 · '+(x.clientName||'未命名')):'空闲'}
      p.appendChild(pillC);
      if(x.disabled){var pillD=document.createElement('span');pillD.className='pill err';pillD.textContent='已禁用';p.appendChild(pillD)}
      h.appendChild(p);c.appendChild(h);
      var m=document.createElement('div');m.className='meta';
      m.appendChild(document.createTextNode('最近活动 '+(x.lastActive?fmtAgo(x.lastActive):'-')+'　'));
      if(x.clientOnline)m.appendChild(document.createTextNode('本次连接自 '+fmtTime(x.clientSince)+'　'));
      m.appendChild(document.createTextNode('ID '));
      var code=document.createElement('code');code.textContent=x.id;m.appendChild(code);
      c.appendChild(m);
      var a=document.createElement('div');a.className='actions';
      if(cooling){
        var allow=document.createElement('button');allow.className='primary';allow.textContent='允许重连';
        allow.onclick=async function(){try{await api('/api/devices/'+x.id+'/allow',{method:'POST'});keepDev[x.id]=Date.now()+120000;toast('已允许重连');await refresh()}catch(e){toast('操作失败')}};
        a.appendChild(allow);
      } else {
        var kick=document.createElement('button');kick.innerHTML=ICO_UNLINK+'断开占用';kick.disabled=!x.clientOnline;
        kick.onclick=async function(){try{await api('/api/devices/'+x.id+'/kick',{method:'POST'});toast('已断开并冷却 5 分钟');await refresh()}catch(e){toast('操作失败')}};
        a.appendChild(kick);
      }
      var tgl=document.createElement('button');tgl.className=x.disabled?'':'danger';tgl.innerHTML=(x.disabled?ICO_CHECK+'启用':ICO_BAN+'禁用');
      tgl.onclick=async function(){
        var opts=x.disabled?{title:'启用设备',message:'启用「'+x.name+'」？控制端可以重新连接。',okText:'启用'}:{title:'禁用设备',message:'禁用「'+x.name+'」？\n禁用后控制端无法连接本设备（设备自身保持在线）；随时可以再启用。',danger:true,okText:'禁用'};
        if(!(await confirmDialog(opts)))return;
        try{await api('/api/devices/'+x.id+(x.disabled?'/enable':'/disable'),{method:'POST'});if(x.disabled)keepDev[x.id]=Date.now()+120000;toast(x.disabled?'已启用':'已禁用');await refresh()}catch(e){toast('操作失败')}
      };
      a.appendChild(tgl);c.appendChild(a);g.appendChild(c);
    });
    var offs=all.filter(function(x){return !x.agentOnline&&!x.clientOnline});
    if(offs.length){
      var wrap=document.createElement('div');wrap.className='card';
      var hh=document.createElement('div');hh.className='dev-head';
      var nn=document.createElement('div');nn.className='name';nn.textContent='离线设备（'+offs.length+'）';hh.appendChild(nn);
      var pp=document.createElement('div');pp.className='pills';var pl=document.createElement('span');pl.className='pill off';pl.textContent='不在线';pp.appendChild(pl);hh.appendChild(pp);wrap.appendChild(hh);
      var btn=document.createElement('button');btn.textContent=offOpen?'收起':'展开清理';btn.style.marginTop='10px';
      var bodyEl=document.createElement('div');bodyEl.style.display=offOpen?'':'none';bodyEl.style.marginTop='6px';
      offs.forEach(function(x){
        var row=document.createElement('div');row.className='rel';
        var nm=document.createElement('span');nm.className='from';nm.textContent=x.name;row.appendChild(nm);
        var idc=document.createElement('code');idc.textContent=x.id;row.appendChild(idc);
        var when=document.createElement('span');when.className='when';when.textContent='最近 '+(x.lastSeen?fmtAgo(x.lastSeen):'从未上线');row.appendChild(when);
        var f=document.createElement('span');f.className='flex1';row.appendChild(f);
        var del=document.createElement('button');del.className='danger';del.textContent='删除';
        del.onclick=async function(){
          var okd=await confirmDialog({title:'删除离线设备',message:'删除「'+x.name+'」的登记记录？\n它若还在使用：下次上线会自动重新登记；桌面被控端还会自动补登记本机凭证（无缝恢复），命令行版被控端需要重新生成邀请码。被禁用的设备删除后仍保持封禁。',danger:true,okText:'删除'});
          if(!okd)return;
          try{await api('/api/devices/'+x.id+'/forget',{method:'POST'});toast('已删除');await refresh()}catch(e){toast('删除失败: '+e.message)}
        };
        row.appendChild(del);bodyEl.appendChild(row);
      });
      btn.onclick=function(){offOpen=!offOpen;bodyEl.style.display=offOpen?'':'none';btn.textContent=offOpen?'收起':'展开清理'};
      wrap.appendChild(btn);wrap.appendChild(bodyEl);g.appendChild(wrap);
    }
  }else if(tab==='clients'){
    var c2=await api('/api/clients');var dl=c2.devices||[];
    var dv3=await api('/api/devices');var agentOn={};var devOff={};(dv3.devices||[]).forEach(function(d){agentOn[d.id]=!!d.agentOnline;devOff[d.id]=!!d.disabled});
    var rows=[];dl.forEach(function(dv){(dv.clients||[]).forEach(function(z){rows.push({dev:dv.name,devId:dv.id,z:z})})});
    var onlineN=rows.filter(function(r){return r.z.online}).length;
    var disN=rows.filter(function(r){return r.z.disabled}).length;
    function coolAct(z){return !!(z.cooldownUntil&&(new Date(z.cooldownUntil).getTime()>Date.now()))}
    // 只显示在线的（离线不占卡片）；被禁用 / 设备被禁用 / 冷却中 / 刚操作过的保留显示
    var show=rows.filter(function(r){var k=r.devId+':'+r.z.id;return r.z.online||r.z.disabled||devOff[r.devId]||coolAct(r.z)||(keepAlive[k]&&keepAlive[k]>Date.now())||(keepDev[r.devId]&&keepDev[r.devId]>Date.now())});
    var offHidden=rows.length-show.length;
    $('summary').textContent=rows.length?('A 在线 '+onlineN+(disN?(' · 已禁用 '+disN):'')+(offHidden?(' · 另有 '+offHidden+' 个离线'):'')):'还没有控制端凭证';
    var cg=$('clientGrid');cg.innerHTML='';
    if(!show.length){cg.innerHTML='<div class="card empty">当前没有控制端在线'+(rows.length?'（离线的不显示）':'。B 端生成邀请码、控制端连接后，这里会出现对应卡片')+'。</div>';return}
    show.sort(function(a,b){var av=(a.z.online?2:0)+(a.z.disabled?0:1),bv=(b.z.online?2:0)+(b.z.disabled?0:1);return bv-av});
    show.forEach(function(r){
      var x=r.z;
      var c=document.createElement('div');c.className='card cli'+(x.online?' on':'');
      var h=document.createElement('div');h.className='dev-head';
      var n=document.createElement('div');n.className='name';n.textContent=x.name||x.label||'未命名控制端';h.appendChild(n);
      var p=document.createElement('div');p.className='pills';
      var pill=document.createElement('span');pill.className='pill '+(x.online?'on':'off');pill.textContent=x.online?'A 在线':'A 离线';p.appendChild(pill);
      var cooling=coolAct(x);
      var pillT=document.createElement('span');
      if(cooling){pillT.className='pill warn';pillT.textContent='已断开 · 冷却 '+fmtLeft(x.cooldownUntil)}
      else if(x.online&&x.controlling){var waiting=!agentOn[r.devId];pillT.className='pill '+(waiting?'warn':'busy');pillT.textContent=(waiting?'等待 ':'控制 ')+r.dev}
      else if(x.online){pillT.className='pill';pillT.textContent='待命'}
      else{pillT.className='pill';pillT.textContent='等待重连…'}
      p.appendChild(pillT);
      if(x.disabled){var pd=document.createElement('span');pd.className='pill err';pd.textContent='已禁用';p.appendChild(pd)}
      else if(devOff[r.devId]){var pe=document.createElement('span');pe.className='pill err';pe.textContent='设备已禁用';p.appendChild(pe)}
      h.appendChild(p);c.appendChild(h);
      var m=document.createElement('div');m.className='meta';
      m.appendChild(document.createTextNode('最近活动 '+(x.lastSeen?fmtAgo(x.lastSeen):'-')+'　'));
      if(x.online&&x.since)m.appendChild(document.createTextNode('本次连接自 '+fmtTime(x.since)+'　'));
      m.appendChild(document.createTextNode('ID '));
      var code=document.createElement('code');code.textContent=x.id;m.appendChild(code);
      c.appendChild(m);
      var a=document.createElement('div');a.className='actions';
      if(cooling){
        var allow=document.createElement('button');allow.className='primary';allow.textContent='允许重连';
        allow.onclick=async function(){try{await api('/api/devices/'+r.devId+'/allow',{method:'POST'});keepDev[r.devId]=Date.now()+120000;toast('已允许重连');await refresh()}catch(e){toast('操作失败')}};
        a.appendChild(allow);
      } else {
        var kick=document.createElement('button');kick.innerHTML=ICO_UNLINK+'断开占用';kick.disabled=!x.controlling;
        kick.onclick=async function(){try{await api('/api/devices/'+r.devId+'/kick',{method:'POST'});toast('已断开并冷却 5 分钟');await refresh()}catch(e){toast('操作失败')}};
        a.appendChild(kick);
      }
      var tgl=document.createElement('button');tgl.className=x.disabled?'':'danger';tgl.innerHTML=(x.disabled?ICO_CHECK+'启用':ICO_BAN+'禁用');
      tgl.onclick=async function(){
        var nm=x.name||x.label||'未命名';
        var opts=x.disabled?{title:'启用控制端',message:'启用「'+nm+'」？它可以重新连接 '+r.dev+'。',okText:'启用'}:{title:'禁用控制端',message:'禁用「'+nm+'」？\n禁用后该凭证无法连接 '+r.dev+'（在线连接会被立即断开）；随时可以再启用。',danger:true,okText:'禁用'};
        if(!(await confirmDialog(opts)))return;
        try{await api('/api/clients/'+r.devId+'/'+x.id+(x.disabled?'/enable':'/disable'),{method:'POST'});if(x.disabled)keepAlive[r.devId+':'+x.id]=Date.now()+120000;toast(x.disabled?'已启用':'已禁用');await refresh()}catch(e){toast('操作失败')}
      };
      a.appendChild(tgl);c.appendChild(a);
      cg.appendChild(c);
    });
  }else{
    if(auditNeedReload){var r=await api('/api/audit?n=100');auditEntries=r.entries||[];auditNeedReload=false;renderAudit();}
  }
}catch(e){if(e&&e.message&&e.message!=='unauthorized')toast('加载失败: '+e.message)}}
var LABELS={connect:'连接',disconnect:'断开',kick:'断开占用','device-self-register':'自助登记','device-disable':'禁用','device-enable':'启用','device-allow':'允许重连','device-forget':'删除离线登记','client-add':'新增控制端','client-del':'吊销控制端','client-disable':'禁用控制端','client-enable':'启用控制端'};
var auditEntries=[],auditNeedReload=true,offOpen=false;
function renderAudit(){var tb=$('auditBody');tb.innerHTML='';auditEntries.forEach(function(e){var tr=document.createElement('tr');var td1=document.createElement('td');td1.className='mono';td1.textContent=fmtTime(e.time);tr.appendChild(td1);var td2=document.createElement('td');td2.textContent=actionLabel(e.action);tr.appendChild(td2);var td3=document.createElement('td');td3.textContent=e.deviceName||e.device||'-';tr.appendChild(td3);var td4=document.createElement('td');td4.textContent=[e.detail,e.user,e.durationMs?((e.durationMs/1000).toFixed(0)+'s'):''].filter(Boolean).join(' · ');tr.appendChild(td4);tb.appendChild(tr);});var c=$('auditCount');if(c)c.textContent='已加载 '+auditEntries.length+' 条（自动保留最近 3 天）';var b=$('btnMoreAudit');if(b)b.style.display=auditEntries.length?'':'none';}
async function moreAudit(){if(!auditEntries.length)return;var oldest=auditEntries[auditEntries.length-1].time;try{var r=await api('/api/audit?n=100&before='+encodeURIComponent(oldest));var add=r.entries||[];if(!add.length){toast('没有更早的记录了（只保留最近 3 天）');return}auditEntries=auditEntries.concat(add);renderAudit();toast('已加载 '+add.length+' 条','ok')}catch(e){toast('加载失败: '+e.message)}}
function manualRefresh(){auditNeedReload=true;refresh()}
var ICO_UNLINK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:5px"><path d="M18.84 12.25l1.72-1.71a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M5.17 11.75l-1.71 1.71a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
var ICO_BAN='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" style="vertical-align:-2px;margin-right:5px"><circle cx="12" cy="12" r="9"/><line x1="5.6" y1="5.6" x2="18.4" y2="18.4"/></svg>';
var ICO_CHECK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:5px"><path d="M20 6L9 17l-5-5"/></svg>';
function actionLabel(a){return LABELS[a]||a}
async function boot(){try{me=await api('/api/me');if(me&&me.name)showMain();else showLogin()}catch(e){if(!$('bootView').classList.contains('hidden'))showLogin()}refresh();clearInterval(timer);timer=setInterval(refresh,5000)}
boot();
document.addEventListener('keydown',function(e){if(e.key==='Enter'&&!$('loginView').classList.contains('hidden'))doLogin()});
</script>
</body>
</html>`
