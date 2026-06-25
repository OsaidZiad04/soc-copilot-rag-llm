
const defaultApiUrl = window.location.origin || 'http://127.0.0.1:8001';
const apiInputEl = document.getElementById('api-url');
if (apiInputEl && !apiInputEl.value.trim()) apiInputEl.value = defaultApiUrl;
const API=()=>document.getElementById('api-url').value.replace(/\/$/,'');
let aType='alert', events=[], chatHist=[], refData={}, refPlatform='all', selFile=null, yaraScanFile=null, curUUID=null, lastUploadedProjectFile=null, lastChatContext='', adminSelFile=null, adminSelFiles=[], adminSkippedDuplicateCount=0, adminTab='upload', mitreLiveTimer=null, mitreKickoffTimers=[], mitreWaveIndex=0, sigmaSelectedFileName='', sigmaLastResult=null;
let lastFileAnalysisResult=null, lastAttackTimelineEvents=[], lastIncidentReportText='', invAutoCorrelated=false;
let attackMapStore={};

const pageMeta={dashboard:{t:'Dashboard',s:'Security Overview'},analyzer:{t:'Alert Analyzer',s:'RAG + LLM analysis'},fileanalysis:{t:'File Analysis',s:'Upload -> chunk -> index -> analyze -> chat'},investigation:{t:'Investigation Chain',s:'Multi-event correlation'},attackmap:{t:'Attack Map',s:'Live network IOC map'},ioc:{t:'IOC Enrichment',s:'VirusTotal - AbuseIPDB - Shodan'},
      sigma:{t:'Sigma Converter',s:'SIEM - IDS - EDR/XDR translation'},yarascanner:{t:'YARA Scanner',s:'Static detection with project KB rules'},chat:{t:'AI Security Chat',s:'Ask from the indexed file inside the current project'},reference:{t:'Event ID Reference',s:'Windows & Sysmon events'},history:{t:'Analysis History',s:'All past analyses'},admin:{t:'Admin Settings',s:'Manage typed knowledge sources for RAG'}};

const QUICK_URLS={
  'MITRE ATT&CK':{
    url:'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    type:'mitre_data',
    name:'MITRE ATT&CK Enterprise',
    description:'Enterprise ATT&CK techniques and tactics'
  },
  'NVD 2024':{
    url:'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz',
    type:'cve',
    name:'NVD CVE 2024',
    description:'NVD CVE 2.0 feed for 2024'
  },
  'Malware Bazaar':{
    url:'https://bazaar.abuse.ch/export/csv/recent/',
    type:'malware_report',
    name:'Malware Bazaar Recent',
    description:'Recent public malware feed CSV export'
  },
  'CISA Advisories':{
    url:'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type:'cve',
    name:'CISA KEV',
    description:'Known Exploited Vulnerabilities feed'
  },
  'Sigma Rules':{
    url:'https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml',
    type:'sigma_rule',
    name:'Sigma Windows Rules',
    description:'Example Sigma rule source'
  }
};

function startApp(){
  document.getElementById('welcome-screen').style.display='none';
  document.getElementById('app-shell').classList.remove('hidden');
  const fileNav=document.querySelector(".nav-item[onclick=\"showPage('fileanalysis',this)\"]");
  showPage('fileanalysis',fileNav);
  loadDash();
  clearChat();
}

function showPage(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(el)el.classList.add('active');
  const m=pageMeta[id];if(m){document.getElementById('ptitle').textContent=m.t;document.getElementById('psub').textContent=m.s;}
  if(id==='dashboard')loadDash();
  if(id==='history')loadHist();
  if(id==='reference')loadRef();
  if(id==='admin')loadKBStats();
  if(id==='attackmap')renderAttackMap();
  if(id==='ioc')restoreIOCAPIKeys();
}

function notify(msg,type='info'){const el=document.getElementById('notif');el.textContent=msg;el.className=`notif n-${type} show`;setTimeout(()=>el.classList.remove('show'),3200);}

async function parseApiError(res,path=''){
  const fallback={signal:res.statusText||'request_failed',detail:res.statusText||'Request failed'};
  const body=await res.json().catch(async()=>{
    const text=await res.text().catch(()=>res.statusText);
    return {signal:text||fallback.signal,detail:text||fallback.detail};
  });
  const detail=body.detail||body.message||body.signal||fallback.detail;
  const endpoint=body.endpoint||path;
  return new Error(`${endpoint||'API request'} failed (${res.status}): ${detail}`);
}

async function apiFetch(path,opts={}){
  const url=API()+path;
  const res=await fetch(url,{headers:{'Content-Type':'application/json'},...opts});
  if(!res.ok)throw await parseApiError(res,path);
  return res.json();
}

function getProjectId(){return document.getElementById('proj-id').value||'1';}
function getChunkSize(){return parseInt(document.getElementById('chunk-sz')?.value)||100;}

async function uploadProjectFile(file,pid,contentType='file_analysis'){
  const fd=new FormData();fd.append('file',file);fd.append('content_type',contentType);
  const path=`/api/v1/data/upload/${pid}`;
  const res=await fetch(`${API()}${path}`,{method:'POST',body:fd});
  if(!res.ok)throw await parseApiError(res,path);
  return res.json();
}

async function rebuildProjectIndex(pid,{fileId=null,chunkSize=100,contentType='malware_report',processAll=false}={}){
  const processBody={chunk_size:chunkSize,overlap_size:20,do_reset:1,content_type:contentType};
  if(fileId && !processAll)processBody.file_id=fileId;
  const processRes=await apiFetch(`/api/v1/data/process/${pid}`,{method:'POST',body:JSON.stringify(processBody)});
  const pushRes=await apiFetch(`/api/v1/nlp/index/push/${pid}`,{method:'POST',body:JSON.stringify({do_reset:1})});
  return {process:processRes,push:pushRes};
}

const IOC_GROUPS=[
  {key:'ip_addresses',label:'IP',type:'ip',tone:'net',bucket:'Network',enrichable:true},
  {key:'domains',label:'DOMAIN',type:'domain',tone:'net',bucket:'Network',enrichable:true},
  {key:'urls',label:'URL',type:'url',tone:'net',bucket:'Network',enrichable:true},
  {key:'file_hashes',label:'HASH',type:'hash',tone:'hash',bucket:'File',enrichable:true},
  {key:'file_paths',label:'PATH',type:'file_path',tone:'host',bucket:'Host',enrichable:false},
  {key:'registry_keys',label:'REG',type:'registry_key',tone:'host',bucket:'Host',enrichable:false},
  {key:'cve_ids',label:'CVE',type:'cve',tone:'vuln',bucket:'Vulnerability',enrichable:false},
  {key:'email_addresses',label:'EMAIL',type:'email',tone:'id',bucket:'Identity',enrichable:false},
  {key:'users',label:'USER',type:'user',tone:'id',bucket:'Identity',enrichable:false},
  {key:'processes',label:'PROC',type:'process',tone:'host',bucket:'Host',enrichable:false}
];
let iocRenderStore={}, sigmaConversionStore={}, sigmaConversionSeq=0;

function escapeHTML(value=''){
  return String(value??'').replace(/[&<>"']/g,ch=>({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[ch]));
}

function shortIOCValue(value='',max=92){
  const text=String(value??'');
  if(text.length<=max)return text;
  const head=Math.ceil((max-3)*0.62);
  const tail=Math.floor((max-3)*0.38);
  return `${text.slice(0,head)}...${text.slice(-tail)}`;
}

function normalizeIOCInput(value=''){
  return String(value||'')
    .trim()
    .replace(/\[\.\]/g,'.')
    .replace(/\(\.\)/g,'.')
    .replace(/^hxxps:\/\//i,'https://')
    .replace(/^hxxp:\/\//i,'http://')
    .replace(/[),;:\]}]+$/g,'');
}

function isValidIP(value=''){
  const parts=String(value||'').split('.');
  return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)>=0&&Number(part)<=255);
}

function isValidURL(value=''){
  try{
    const url=new URL(value);
    return ['http:','https:','ftp:'].includes(url.protocol)&&Boolean(url.hostname)&&!isValidIP(url.hostname);
  }catch(e){return false;}
}

function isValidDomain(value=''){
  const domain=String(value||'').toLowerCase().replace(/\.$/,'');
  if(!domain||isValidIP(domain)||domain.includes('/')||domain.includes('\\')||domain.includes('@'))return false;
  if(!/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain))return false;
  const badSuffixes=new Set(['exe','dll','ps1','bat','cmd','sys','tmp','log','txt','zip','rar','7z','pdf','doc','docx','php','asp','aspx','jsp','cgi','pl','bin']);
  if(badSuffixes.has(domain.split('.').pop()))return false;
  const fileLike=/\b(?:shell|payload|dropper|loader|beacon|stage|update|install|setup|backup)\.[a-z0-9]{2,5}$/i;
  return !fileLike.test(domain);
}

function normalizeIOCItem(raw,group){
  const value=normalizeIOCInput(raw);
  if(!value)return null;
  if(group.type==='ip'&&!isValidIP(value))return null;
  if(group.type==='domain'&&!isValidDomain(value))return null;
  if(group.type==='url'&&!isValidURL(value))return null;
  if(group.type==='hash'&&!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value))return null;
  return value;
}

function valuesFromIOCGroup(iocs={},key){
  const aliases={
    email_addresses:['email_addresses','emails'],
    file_hashes:['file_hashes','hashes','hash'],
    ip_addresses:['ip_addresses','ips'],
    cve_ids:['cve_ids','cves']
  };
  const keys=aliases[key]||[key];
  return keys.flatMap(k=>Array.isArray(iocs[k])?iocs[k]:[]);
}

function flattenIOCs(iocs={}){
  const seen=new Set();
  const items=[];
  IOC_GROUPS.forEach(group=>{
    valuesFromIOCGroup(iocs,group.key).forEach(raw=>{
      const value=normalizeIOCItem(raw,group);
      if(!value)return;
      const dedupeKey=`${group.type}:${value.toLowerCase()}`;
      if(seen.has(dedupeKey))return;
      seen.add(dedupeKey);
      items.push({...group,value});
    });
  });
  return items;
}

function isPublicIP(value=''){
  if(!isValidIP(value))return false;
  const [a,b]=String(value).split('.').map(Number);
  if(a===0||a===10||a===127||a===255)return false;
  if(a===172&&b>=16&&b<=31)return false;
  if(a===192&&b===168)return false;
  if(a===169&&b===254)return false;
  if(a===100&&b>=64&&b<=127)return false;
  if(a>=224)return false;
  return true;
}

function cleanAttackMapText(value=''){
  return String(value??'').trim();
}

function mergeAttackMapNode(ip,data={}){
  ip=normalizeIOCInput(ip);
  if(!isPublicIP(ip))return;
  const existing=attackMapStore[ip]||{ip,source:new Set(),ports:new Set(),firstSeen:Date.now()};
  const merged={...existing,...data,ip,lastSeen:Date.now()};
  merged.source=existing.source instanceof Set?existing.source:new Set(existing.source||[]);
  if(data.source)merged.source.add(data.source);
  merged.ports=existing.ports instanceof Set?existing.ports:new Set(existing.ports||[]);
  (Array.isArray(data.ports)?data.ports:[]).forEach(port=>merged.ports.add(String(port)));
  ['country','asn','org','verdict','risk','confidence'].forEach(key=>{
    if(data[key]!==undefined&&data[key]!==null&&String(data[key]).trim()!=='')merged[key]=data[key];
  });
  attackMapStore[ip]=merged;
  renderAttackMap();
}

function addAttackMapIOCsFromAnalysis(iocs={}){
  clearAttackMapSource('File Analysis');
  const ips=flattenIOCs(iocs).filter(item=>item.type==='ip');
  ips.forEach(item=>mergeAttackMapNode(item.value,{
    source:'File Analysis',
    verdict:lastFileAnalysisResult?.severity?.level||'observed',
    confidence:lastFileAnalysisResult?.severity?.confidence
  }));
  if(!ips.length)renderAttackMap();
}

function clearAttackMapSource(source){
  Object.keys(attackMapStore).forEach(ip=>{
    const node=attackMapStore[ip];
    const sources=node.source instanceof Set?node.source:new Set(node.source||[]);
    sources.delete(source);
    if(!sources.size)delete attackMapStore[ip];
    else attackMapStore[ip]={...node,source:sources};
  });
}

function addAttackMapIOCsFromEnrichment(results=[]){
  results.filter(r=>r?.type==='ip'&&isPublicIP(r.value)).forEach(r=>{
    const vt=r.virustotal||{}, ab=r.abuseipdb||{}, sh=r.shodan||{}, ipwhois=r.ipwhois||{};
    mergeAttackMapNode(r.value,{
      source:'IOC Enrichment',
      country:cleanAttackMapText(ipwhois.country||vt.country||ab.country||''),
      asn:cleanAttackMapText(ipwhois.connection?.asn||vt.asn||''),
      org:cleanAttackMapText(ipwhois.connection?.org||ab.isp||vt.as_owner||''),
      verdict:r.verdict||r.priority?.label||'observed',
      risk:r.priority?.level||r.verdict||'informational',
      confidence:r.confidence,
      ports:Array.isArray(sh.ports)?sh.ports:[]
    });
  });
}

function attackMapTone(node={}){
  const text=`${node.verdict||''} ${node.risk||''}`.toLowerCase();
  if(/critical|malicious|p1/.test(text))return 'critical';
  if(/high|suspicious|p2/.test(text))return 'high';
  if(/medium|p3/.test(text))return 'medium';
  return 'info';
}

function attackMapPosition(index,total){
  const slots=[
    {x:16,y:22},{x:29,y:14},{x:72,y:18},{x:86,y:30},{x:78,y:70},{x:60,y:84},
    {x:34,y:78},{x:13,y:62},{x:46,y:18},{x:88,y:54},{x:23,y:48},{x:67,y:42}
  ];
  if(index<slots.length)return slots[index];
  const angle=(Math.PI*2*index)/Math.max(total,1)-Math.PI/2;
  return {x:50+Math.cos(angle)*38,y:50+Math.sin(angle)*34};
}

function renderAttackMap(){
  const canvas=document.getElementById('attack-map-canvas');
  if(!canvas)return;
  const nodes=Object.values(attackMapStore).filter(n=>isPublicIP(n.ip)).sort((a,b)=>{
    const toneOrder={critical:0,high:1,medium:2,info:3};
    return toneOrder[attackMapTone(a)]-toneOrder[attackMapTone(b)]||a.ip.localeCompare(b.ip);
  });
  const countrySet=new Set(nodes.map(n=>n.country).filter(Boolean));
  const highRisk=nodes.filter(n=>['critical','high'].includes(attackMapTone(n))).length;
  const portSet=new Set(nodes.flatMap(n=>Array.from(n.ports||[])));
  const setText=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=value;};
  setText('am-total',nodes.length);
  setText('am-countries',countrySet.size);
  setText('am-highrisk',highRisk);
  setText('am-ports',portSet.size);
  if(!nodes.length){
    canvas.innerHTML='<div class="attack-map-empty">No public IP indicators available. Analyze a file or enrich IOCs first.</div>';
    return;
  }
  const target={x:50,y:50};
  const positioned=nodes.map((node,index)=>({...node,pos:attackMapPosition(index,nodes.length),tone:attackMapTone(node)}));
  const lines=positioned.map((node,index)=>`
    <line class="attack-map-line attack-map-line-${node.tone}" x1="${node.pos.x}%" y1="${node.pos.y}%" x2="${target.x}%" y2="${target.y}%" style="animation-delay:${index*.18}s"></line>
    <circle class="attack-map-pulse attack-map-pulse-${node.tone}" cx="${target.x}%" cy="${target.y}%" r="${5+index%3}" style="animation-delay:${index*.22}s"></circle>`).join('');
  const cards=positioned.map((node,index)=>{
    const ports=Array.from(node.ports||[]).slice(0,8);
    const sources=Array.from(node.source||[]).join(' + ')||'Observed';
    const org=[node.asn?`ASN ${node.asn}`:'',node.org||''].filter(Boolean).join(' - ');
    return `<div class="attack-map-node attack-map-node-${node.tone}" style="left:${node.pos.x}%;top:${node.pos.y}%;animation-delay:${index*.06}s">
      <div class="attack-map-node-head">
        <span class="attack-map-dot"></span>
        <span class="attack-map-risk">${escapeHTML(String(node.verdict||node.risk||'observed').toUpperCase())}</span>
      </div>
      <div class="attack-map-ip">${escapeHTML(node.ip)}</div>
      <div class="attack-map-meta">${escapeHTML(node.country||'Country unknown')}</div>
      <div class="attack-map-meta">${escapeHTML(org||'ASN / organization unavailable')}</div>
      <div class="attack-map-source">${escapeHTML(sources)}</div>
      <div class="attack-map-ports">${ports.length?ports.map(port=>`<span>${escapeHTML(port)}</span>`).join(''):'<em>No open ports observed</em>'}</div>
    </div>`;
  }).join('');
  canvas.innerHTML=`
    <div class="attack-map-grid"></div>
    <svg class="attack-map-lines" viewBox="0 0 100 100" preserveAspectRatio="none">${lines}</svg>
    <div class="attack-map-target" style="left:${target.x}%;top:${target.y}%">
      <div class="attack-map-target-core">SOC</div>
      <div class="attack-map-target-label">Protected Environment</div>
    </div>
    ${cards}`;
}

function iocStats(items=[]){
  const stats={total:items.length,enrichable:0,Network:0,File:0,Host:0,Identity:0,Vulnerability:0};
  items.forEach(item=>{
    if(item.enrichable)stats.enrichable+=1;
    stats[item.bucket]=(stats[item.bucket]||0)+1;
  });
  return stats;
}

function renderIOCMarkup(iocs={},options={}){
  const items=flattenIOCs(iocs);
  if(!items.length)return '<span style="color:var(--text3);font-size:10px;">No IOCs</span>';

  const stats=iocStats(items);
  const storeKey=options.sourceKey||`ioc-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const enrichable=items.filter(item=>item.enrichable).map(item=>({value:item.value,type:item.type}));
  iocRenderStore[storeKey]=enrichable;
  const rows=items.map(item=>`
    <div class="ioc-row ioc-row-${item.tone}" title="${escapeHTML(item.value)}">
      <span class="ioc-type">${item.label}</span>
      <span class="ioc-val">${escapeHTML(shortIOCValue(item.value,item.type==='hash'?74:108))}</span>
      <span class="ioc-bucket">${item.bucket}</span>
    </div>`).join('');
  const focus=[
    stats.Network?`Network pivots: ${stats.Network}`:'',
    stats.File?`File artifacts: ${stats.File}`:'',
    stats.Host?`Host artifacts: ${stats.Host}`:'',
    stats.Identity?`Identity pivots: ${stats.Identity}`:'',
    stats.Vulnerability?`CVEs: ${stats.Vulnerability}`:''
  ].filter(Boolean);

  return `<div class="ioc-pack">
    <div class="ioc-summary-strip">
      <div class="ioc-stat"><span>Total</span><strong>${stats.total}</strong></div>
      <div class="ioc-stat"><span>Enrichable</span><strong>${stats.enrichable}</strong></div>
      <div class="ioc-stat"><span>Network</span><strong>${stats.Network}</strong></div>
      <div class="ioc-stat"><span>Host/File</span><strong>${stats.Host+stats.File}</strong></div>
      ${enrichable.length?`<button class="btn-sec ioc-inline-btn" onclick="sendIOCsToEnrichment('${storeKey}')">Enrich</button>`:''}
    </div>
    ${focus.length?`<div class="ioc-focus-row">${focus.map(item=>`<span>${escapeHTML(item)}</span>`).join('')}</div>`:''}
    <div class="ioc-row-list">${rows}</div>
  </div>`;
}

function sendIOCsToEnrichment(storeKey){
  const items=iocRenderStore[storeKey]||[];
  if(!items.length){notify('No enrichable IOCs found','info');return;}
  const seen=new Set();
  iocList=items.filter(item=>{
    const key=`${item.type}:${item.value.toLowerCase()}`;
    if(seen.has(key))return false;
    seen.add(key);
    return true;
  });
  const nav=document.querySelector(".nav-item[onclick=\"showPage('ioc',this)\"]");
  showPage('ioc',nav);
  renderIOCs();
  document.getElementById('ioc-results').innerHTML='<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:40px;text-align:center;color:var(--text3);font-size:11px;">Ready to enrich selected IOCs</div>';
  notify(`Loaded ${iocList.length} IOC(s) for enrichment`,'ok');
}

function ruleValue(rules={},keys=[]){
  for(const key of keys){
    const value=rules?.[key];
    if(value!==null&&value!==undefined&&value!==''&&!(Array.isArray(value)&&!value.length))return value;
  }
  return null;
}

function normalizeDetectionRules(rules={}){
  return {
    sigma_rule:ruleValue(rules,['sigma_rule','sigma','sigma_yml','sigma_yaml','sigma_query']),
    splunk_spl:ruleValue(rules,['splunk_spl','splunk','spl']),
    elk_query:ruleValue(rules,['elk_query','elastic_query','kql']),
    suricata_rule:ruleValue(rules,['suricata_rule','suricata']),
    yara_rule:ruleValue(rules,['yara_rule','yara'])
  };
}

function formatRuleCode(value){
  if(typeof value==='string')return value;
  return JSON.stringify(value,null,2);
}

function registerSigmaRule(value,sourceRules={}){
  const key=`sigma-${++sigmaConversionSeq}`;
  sigmaConversionStore[key]={sigma:formatRuleCode(value),sourceRules};
  return key;
}

function summarizeSigmaText(sigma=''){
  const lines=String(sigma||'').split(/\r?\n/);
  const title=(lines.find(line=>line.trim().toLowerCase().startsWith('title:'))||'').replace(/^\s*title:\s*/i,'').trim().replace(/^['"]|['"]$/g,'');
  const selectors=new Set();
  let inDetection=false;

  lines.forEach(line=>{
    const trimmed=line.trim();
    if(!trimmed||trimmed.startsWith('#'))return;
    if(/^detection\s*:\s*$/i.test(trimmed)){inDetection=true;return;}
    if(!inDetection)return;
    if(/^\S/.test(line)&&!/^detection\s*:/i.test(trimmed)){inDetection=false;return;}
    const match=line.match(/^\s{2}([A-Za-z0-9_*.-]+)\s*:\s*(?:$|#)/);
    if(match&&match[1].toLowerCase()!=='condition')selectors.add(match[1]);
  });

  return {title,selectorCount:selectors.size};
}

function renderSigmaIssues(errors=[],warnings=[]){
  const items=[
    ...(errors||[]).map(item=>({...item,type:'error'})),
    ...(warnings||[]).map(item=>({...item,type:'warning'}))
  ];
  if(!items.length)return '';
  return `<div class="sigma-issues">
    ${items.map(item=>`<div class="sigma-issue sigma-issue-${item.type}">
      <span>${escapeHTML((item.code||item.type).toUpperCase())}</span>
      <strong>${escapeHTML(item.field||'sigma')}</strong>
      <div>${escapeHTML(item.message||'')}</div>
    </div>`).join('')}
  </div>`;
}

function renderSigmaApiResults(result={}){
  const rule=result.rule||{};
  const conversions=result.conversions||[];
  const selectors=result.selectors||{};
  const selectorCount=Object.keys(selectors).length;
  const conversionCards=conversions.map(item=>`<div class="sigma-conversion-card">
    <div class="sigma-conversion-label">${escapeHTML(item.name||item.platform||'Query')} <span>${escapeHTML(item.category||'')}</span></div>
    <div class="sigma-conversion-code">${escapeHTML(item.query||'No query generated')}</div>
    ${renderSigmaIssues(item.errors||[],[])}
  </div>`).join('');

  return `<div class="sigma-converter-summary">
      <div><span>Rule</span><strong>${escapeHTML(rule.title||'Untitled Sigma Rule')}</strong></div>
      <div><span>Selectors</span><strong>${selectorCount}</strong></div>
      <div><span>Outputs</span><strong>${conversions.length}</strong></div>
    </div>
    ${renderSigmaIssues(result.errors||[],result.warnings||[])}
    <div class="sigma-conversions"><div class="sigma-conversion-grid">${conversionCards||'<div class="sigma-converter-empty">No conversions generated</div>'}</div></div>`;
}

function setSigmaConverterInput(sigma){
  const input=document.getElementById('sigma-converter-input');
  const results=document.getElementById('sigma-converter-results');
  if(!input||!results)return false;
  sigmaLastResult=null;
  input.value=sigma||'';
  const summary=summarizeSigmaText(sigma||'');
  results.innerHTML=`<div class="sigma-converter-summary">
      <div><span>Rule</span><strong>${escapeHTML(summary.title||'Sigma text loaded')}</strong></div>
      <div><span>Selectors</span><strong>${summary.selectorCount}</strong></div>
      <div><span>Selected</span><strong>${getSigmaPlatforms().length}</strong></div>
    </div><div class="sigma-converter-empty">Text is ready. Choose platforms and click Convert.</div>`;
  return true;
}

function openSigmaConverter(sigma){
  const ok=setSigmaConverterInput(sigma);
  if(!ok){notify('Sigma converter field unavailable','err');return;}
  setSigmaSourceMode('text');
  const nav=document.querySelector(".nav-item[onclick=\"showPage('sigma',this)\"]");
  showPage('sigma',nav);
  document.getElementById('sigma-converter-input')?.focus();
  notify('Sigma loaded into converter field','ok');
}

function getSigmaPlatforms(){
  return [...document.querySelectorAll('#sigma-platform-grid input[type="checkbox"]:checked')]
    .map(input=>input.value);
}

function setSigmaPlatforms(checked){
  document.querySelectorAll('#sigma-platform-grid input[type="checkbox"]').forEach(input=>input.checked=checked);
}

function setSigmaSourceMode(mode){
  document.querySelectorAll('.sigma-source-row .tbtn').forEach(btn=>{
    btn.classList.toggle('active',btn.dataset.sourceMode===mode);
  });
}

async function sigmaApiFetch(path,body){
  const res=await fetch(`${API()}${path}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await res.json().catch(()=>({signal:'sigma_request_failed'}));
  if(!res.ok&&!(data.errors||data.warnings))throw new Error(data.detail||data.signal||res.statusText);
  return data;
}

async function convertSigmaField(){
  const input=document.getElementById('sigma-converter-input');
  const results=document.getElementById('sigma-converter-results');
  const sigma=input?.value.trim()||'';
  if(!sigma){notify('Paste Sigma first','err');return;}
  const platforms=getSigmaPlatforms();
  if(!platforms.length){notify('Select at least one platform','err');return;}
  results.innerHTML='<div class="sigma-converter-empty">Converting Sigma...</div>';
  try{
    const data=await sigmaApiFetch('/api/v1/sigma/convert',{sigma_rule:sigma,platforms,filename:sigmaSelectedFileName||null});
    sigmaLastResult=data;
    results.innerHTML=renderSigmaApiResults(data);
    notify(data.valid===false?'Sigma converted with validation errors':'Sigma converted',data.valid===false?'err':'ok');
  }catch(e){
    results.innerHTML=renderSigmaIssues([{field:'sigma_rule',code:'conversion_failed',message:e.message}],[]);
    notify('Sigma conversion failed: '+e.message,'err');
  }
}

async function validateSigmaField(){
  const input=document.getElementById('sigma-converter-input');
  const results=document.getElementById('sigma-converter-results');
  const sigma=input?.value.trim()||'';
  if(!sigma){notify('Paste Sigma first','err');return;}
  try{
    const data=await sigmaApiFetch('/api/v1/sigma/validate',{sigma_rule:sigma,filename:sigmaSelectedFileName||null});
    sigmaLastResult=data;
    results.innerHTML=`<div class="sigma-converter-summary">
      <div><span>Validation</span><strong>${data.valid?'Valid':'Invalid'}</strong></div>
      <div><span>Selectors</span><strong>${Object.keys(data.selectors||{}).length}</strong></div>
      <div><span>Platforms</span><strong>${(data.supported_platforms||[]).length}</strong></div>
    </div>${renderSigmaIssues(data.errors||[],data.warnings||[])||'<div class="sigma-converter-empty">Sigma rule is valid</div>'}`;
    notify(data.valid?'Sigma is valid':'Sigma has validation errors',data.valid?'ok':'err');
  }catch(e){
    results.innerHTML=renderSigmaIssues([{field:'sigma_rule',code:'validation_failed',message:e.message}],[]);
    notify('Sigma validation failed: '+e.message,'err');
  }
}

function clearSigmaConverter(){
  sigmaSelectedFileName='';
  sigmaLastResult=null;
  const input=document.getElementById('sigma-converter-input');
  const results=document.getElementById('sigma-converter-results');
  const fileName=document.getElementById('sigma-file-name');
  if(input)input.value='';
  if(results)results.innerHTML='<div class="sigma-converter-empty">Paste or upload Sigma, then convert</div>';
  if(fileName)fileName.textContent='YAML';
  setSigmaSourceMode('text');
}

function loadSampleSigma(){
  const sample=`title: Suspicious PowerShell Network Connection
id: soc-copilot-sample-powershell-network
status: experimental
logsource:
  product: windows
detection:
  selection_process:
    Image|endswith:
      - powershell.exe
  selection_ip:
    DestinationIp|contains:
      - 185.220.101.45
  condition: selection_process and selection_ip
level: high`;
  setSigmaConverterInput(sample);
  setSigmaSourceMode('text');
  sigmaSelectedFileName='sample_sigma_rule.yml';
  const fileName=document.getElementById('sigma-file-name');
  if(fileName)fileName.textContent='sample_sigma_rule.yml';
}

function focusSigmaText(){
  setSigmaSourceMode('text');
  document.getElementById('sigma-converter-input')?.focus();
}

function openSigmaFilePicker(){
  setSigmaSourceMode('file');
  document.getElementById('sigma-file-input')?.click();
}

function sigmaDragOver(e){e.preventDefault();document.getElementById('sigma-zone').classList.add('dragging');}
function sigmaDrop(e){
  e.preventDefault();
  document.getElementById('sigma-zone').classList.remove('dragging');
  const file=e.dataTransfer.files[0];
  if(file)sigmaReadFile(file);
}
function sigmaSelectFile(e){
  const file=e.target.files[0];
  if(file)sigmaReadFile(file);
}
function sigmaReadFile(file){
  const ext=(file.name.split('.').pop()||'').toLowerCase();
  if(!['yml','yaml'].includes(ext)){notify('Sigma file must be .yml or .yaml','err');return;}
  const reader=new FileReader();
  reader.onload=()=>{
    sigmaSelectedFileName=file.name;
    const fileName=document.getElementById('sigma-file-name');
    if(fileName)fileName.textContent=file.name;
    setSigmaConverterInput(String(reader.result||''));
    setSigmaSourceMode('file');
    notify('Sigma file loaded','ok');
  };
  reader.onerror=()=>notify('Could not read Sigma file','err');
  reader.readAsText(file);
}

function exportSigmaConversions(){
  if(!sigmaLastResult){notify('Convert Sigma before export','err');return;}
  const blob=new Blob([JSON.stringify(sigmaLastResult,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url;
  a.download='sigma-conversions.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toggleSigmaTranslations(btn,key){
  const data=sigmaConversionStore[key];
  if(!data){notify('Sigma conversion data unavailable','err');return;}
  openSigmaConverter(data.sigma);
  btn.classList.add('is-active');
}

function renderRuleBlock(label,value,language,options={}){
  const isSigma=language==='sigma';
  const sigmaKey=isSigma?registerSigmaRule(value,options.sourceRules||{}):'';
  const action=isSigma?`<button type="button" class="rule-convert-btn" title="Open Sigma converter field" aria-label="Open Sigma converter field" onclick="toggleSigmaTranslations(this,'${sigmaKey}')">&#8644;</button>`:'';
  const note=options.note?`<div class="rule-note">${escapeHTML(options.note)}</div>`:'';
  return `<div class="rule-block rule-block-${escapeHTML(language)}"><div class="rule-head"><div class="rule-label">${escapeHTML(label)}</div>${action}</div><div class="rule-code language-${escapeHTML(language)}">${escapeHTML(formatRuleCode(value))}</div>${note}</div>`;
}

function renderRuleMarkup(rules={}){
  const normalized=normalizeDetectionRules(rules);
  let html='';
  if(normalized.sigma_rule)html+=renderRuleBlock('SIGMA',normalized.sigma_rule,'sigma',{sourceRules:normalized});
  if(normalized.splunk_spl)html+=renderRuleBlock('SPLUNK SPL',normalized.splunk_spl,'splunk');
  if(normalized.elk_query)html+=renderRuleBlock('ELK QUERY',normalized.elk_query,'elk');
  if(normalized.suricata_rule)html+=renderRuleBlock('SURICATA',normalized.suricata_rule,'suricata');
  if(normalized.yara_rule)html+=renderRuleBlock('YARA',normalized.yara_rule,'yara');
  return html||'<span style="color:var(--text3);font-size:10px;">No rules</span>';
}

function renderActionMarkup(actions=[]){
  return actions.map(ac=>`<div class="action-item"><span class="ap ap${ac.priority||3}">[P${ac.priority||3}]</span><span>${ac.action}${ac.description?`: ${ac.description}`:''}</span></div>`).join('')||'<span style="color:var(--text3);font-size:10px;">No actions</span>';
}

function prettyLabel(value=''){
  return String(value||'').split(/[_-]/).filter(Boolean).map(part=>part.charAt(0).toUpperCase()+part.slice(1)).join(' ');
}

function tacticToneKey(tactic=''){
  const normalized=String(tactic||'').toLowerCase();
  const map={
    'initial-access':'ia',
    'execution':'ex',
    'persistence':'pe',
    'lateral-movement':'la',
    'command-and-control':'la',
    'discovery':'di',
    'defense-evasion':'di',
    'credential-access':'di',
    'collection':'pe',
    'exfiltration':'la',
    'impact':'ia'
  };
  return map[normalized]||'di';
}

function renderInvPivotPoints(pivots=[]){
  if(!pivots.length)return '<div class="inv-empty">No pivot points derived</div>';
  return `<div class="pivot-grid">${pivots.map(p=>`
    <div class="pivot-chip">
      <div class="pivot-type">${escapeHTML((p.type||'').toUpperCase())}</div>
      <div class="pivot-value">${escapeHTML(p.value||'')}</div>
      <div class="pivot-meta">Seen in events: ${escapeHTML((p.seen_in_events||[]).join(', ')||'-')}</div>
    </div>`).join('')}</div>`;
}

function renderInvKillChain(chain=[]){
  if(!chain.length)return '<div class="inv-empty">No kill chain phases</div>';
  return `<div class="killchain-row">${chain.map(item=>`
    <div class="kill-pill">
      <div class="kill-phase">${escapeHTML(prettyLabel(item.phase||'unknown'))}</div>
      <div class="kill-tech">${escapeHTML((item.techniques||[]).join(', ')||'No techniques')}</div>
      <div class="kill-state">${item.completed===false?'In progress':'Completed'}</div>
    </div>`).join('')}</div>`;
}

function renderInvestigationOverview(inv={},sev={}){
  const confidence=((Number(sev.confidence||0))*100).toFixed(0);
  const fp=((Number(inv.false_positive_likelihood||0))*100).toFixed(0);
  const actor=inv.threat_actor||'Unknown';
  const malware=inv.malware_family||'Unknown';
  const total=inv.total_events_analyzed||(inv.timeline||[]).length||events.length;
  return `<div class="inv-overview">
    <div class="inv-overview-main">
      <div class="inv-overview-kicker">Investigation</div>
      <div class="inv-overview-title">${escapeHTML(inv.investigation_title||'Correlated event investigation')}</div>
      <div class="inv-overview-meta">
        <span>${escapeHTML(String(total))} events</span>
        <span>${escapeHTML(String(confidence))}% confidence</span>
        <span>${escapeHTML(String(fp))}% false positive likelihood</span>
      </div>
    </div>
    <div class="inv-overview-facts">
      <div><span>Actor</span><strong>${escapeHTML(actor)}</strong></div>
      <div><span>Malware</span><strong>${escapeHTML(malware)}</strong></div>
      <div><span>Stage</span><strong>${escapeHTML(prettyLabel(inv.current_stage||'unknown'))}</strong></div>
    </div>
  </div>`;
}

function renderCompactRuleBlocks(rules={}){
  const normalized=normalizeDetectionRules(rules);
  const blocks=[];
  if(normalized.sigma_rule)blocks.push(renderRuleBlock('SIGMA',normalized.sigma_rule,'sigma',{sourceRules:normalized,note:'Prevention: convert this Sigma rule to your SIEM or EDR policy to alert on or block the same attack pattern.'}));
  if(normalized.splunk_spl)blocks.push(renderRuleBlock('SPLUNK SPL',normalized.splunk_spl,'splunk'));
  if(normalized.elk_query)blocks.push(renderRuleBlock('ELK QUERY',normalized.elk_query,'elk'));
  return blocks.join('')||'<div class="inv-empty">No rules generated</div>';
}

function renderSourceStateCard(name,score,detail,extra='',link=''){
  return `<div class="ioc-source">
    <div class="ioc-sname">${escapeHTML(name)}</div>
    <div class="ioc-sscore ok">${escapeHTML(score)}</div>
    <div class="ioc-sdetail">${escapeHTML(detail)}</div>
    ${extra?`<div class="ioc-card-extra">${escapeHTML(extra)}</div>`:''}
    ${link?`<a href="${escapeHTML(link)}" target="_blank" style="font-size:8px;color:var(--cyan);margin-top:3px;display:block;">Open Source</a>`:''}
  </div>`;
}

function renderLocalContextBlock(local={},related=[]){
  const rows=[];
  Object.entries(local||{}).forEach(([key,val])=>{
    if(key==='notes'||key==='related_observables')return;
    if(val===null||val===undefined||val===''||(Array.isArray(val)&&!val.length))return;
    const value=Array.isArray(val)?val.join(', '):(typeof val==='object'?Object.entries(val).map(([k,v])=>`${prettyLabel(k)}: ${v}`).join(' - '):String(val));
    rows.push(`<div class="ioc-kv"><span class="ioc-k">${escapeHTML(prettyLabel(key))}</span><span class="ioc-v">${escapeHTML(value)}</span></div>`);
  });
  const notes=(local.notes||[]).filter(Boolean);
  return `<div class="ioc-context-grid">
    <div class="ioc-context-card">
      <div class="ioc-context-title">Local Context</div>
      ${rows.join('')||'<div class="ioc-context-empty">No local context</div>'}
    </div>
    <div class="ioc-context-card">
      <div class="ioc-context-title">Relationships & Notes</div>
      ${(related||[]).length?`<div class="ioc-rel-list">${related.map(item=>`<span class="ioc-rel">${escapeHTML((item.type||'').toUpperCase())}: ${escapeHTML(item.value||'')}</span>`).join('')}</div>`:'<div class="ioc-context-empty">No related observables</div>'}
      ${notes.length?`<div class="ioc-note-list">${notes.map(note=>`<div class="ioc-note">${escapeHTML(note)}</div>`).join('')}</div>`:''}
    </div>
  </div>`;
}

function prefersReducedMotion(){
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function animateNumber(el,target,{duration=900,decimals=0,suffix=''}={}){
  if(!el)return;
  const finalValue=Number(target||0);
  const startValue=Number(el.dataset.value ?? 0);
  if(prefersReducedMotion()){
    el.textContent=`${finalValue.toFixed(decimals)}${suffix}`;
    el.dataset.value=String(finalValue);
    return;
  }
  if(el._rafId)window.cancelAnimationFrame(el._rafId);
  el.classList.remove('is-counting');
  void el.offsetWidth;
  el.classList.add('is-counting');
  const startTime=performance.now();
  const ease=t=>1-Math.pow(1-t,3);
  const tick=(now)=>{
    const progress=Math.min((now-startTime)/duration,1);
    const value=startValue+((finalValue-startValue)*ease(progress));
    el.textContent=`${value.toFixed(decimals)}${suffix}`;
    if(progress<1){
      el._rafId=window.requestAnimationFrame(tick);
    }else{
      el.dataset.value=String(finalValue);
      window.setTimeout(()=>el.classList.remove('is-counting'),220);
    }
  };
  el._rafId=window.requestAnimationFrame(tick);
}

function pulseBadge(el){
  if(!el)return;
  el.classList.remove('dash-ping');
  void el.offsetWidth;
  el.classList.add('dash-ping');
}

function animateRecentList(){
  const rows=document.querySelectorAll('#page-dashboard #rec-list .alert-item');
  rows.forEach((row,index)=>{
    row.style.setProperty('--recent-delay',`${index*90}ms`);
    row.classList.remove('recent-live');
    void row.offsetWidth;
    row.classList.add('recent-live');
  });
}

function animateDashboardCounters(stats){
  animateNumber(document.getElementById('sc'),stats.critical||0);
  animateNumber(document.getElementById('sh'),stats.high||0);
  animateNumber(document.getElementById('sm'),stats.medium||0);
  animateNumber(document.getElementById('st'),stats.total||0);
  const criticalBadge=document.getElementById('bdg');
  criticalBadge.textContent=stats.critical||0;
  criticalBadge.dataset.value=String(stats.critical||0);
  pulseBadge(criticalBadge);
}

function replayDashboardMotion(){
  const cards=document.querySelectorAll('#page-dashboard .stat-card, #page-dashboard .dash-ops-grid > .card, #page-dashboard .dash-widget, #page-dashboard .dash-chart-card');
  cards.forEach((card,index)=>{
    card.style.setProperty('--panel-delay',`${index*85}ms`);
    card.style.setProperty('--float-delay',`${(index%4)*.42}s`);
    card.classList.remove('dash-live');
    void card.offsetWidth;
    card.classList.add('dash-live');
  });
  document.querySelectorAll('#page-dashboard .stat-value').forEach((value,index)=>{
    value.style.setProperty('--value-delay',`${index*.28}s`);
  });
}

function clearMitreMotion(){
  if(mitreLiveTimer){
    window.clearInterval(mitreLiveTimer);
    mitreLiveTimer=null;
  }
  mitreKickoffTimers.forEach(timer=>window.clearTimeout(timer));
  mitreKickoffTimers=[];
}

function pulseMitreTile(tile){
  if(!tile)return;
  tile.classList.remove('is-hot');
  void tile.offsetWidth;
  tile.classList.add('is-hot');
  if(tile._mitreCooldown)window.clearTimeout(tile._mitreCooldown);
  tile._mitreCooldown=window.setTimeout(()=>tile.classList.remove('is-hot'),1550);
}

function buildMitreTrail(tiles,origin){
  if(!origin)return [];
  const row=Number(origin.dataset.row||0);
  const col=Number(origin.dataset.col||0);
  return [...tiles]
    .filter(tile=>tile!==origin)
    .map(tile=>{
      const tRow=Number(tile.dataset.row||0);
      const tCol=Number(tile.dataset.col||0);
      const distance=Math.abs(tRow-row)+(Math.abs(tCol-col)*0.92);
      return {tile,distance};
    })
    .filter(item=>item.distance<=2.25)
    .sort((a,b)=>a.distance-b.distance)
    .slice(0,3)
    .map(item=>item.tile);
}

function pulseMitreTrail(tiles,origin){
  const trail=[origin,...buildMitreTrail(tiles,origin)];
  trail.forEach((tile,index)=>scheduleMitrePulse(tile,index*150));
}

function scheduleMitrePulse(tile,delay){
  const timer=window.setTimeout(()=>{
    mitreKickoffTimers=mitreKickoffTimers.filter(item=>item!==timer);
    pulseMitreTile(tile);
  },delay);
  mitreKickoffTimers.push(timer);
}

function wireMitreMotion(){
  clearMitreMotion();
  const tiles=[...document.querySelectorAll('#mitre-grid .mc')];
  if(!tiles.length)return;
  tiles.forEach((tile,index)=>{
    tile.style.setProperty('--tile-delay',`${index*58}ms`);
    tile.style.setProperty('--float-delay',`${(index%6)*.24}s`);
    tile.style.setProperty('--float-time',`${((index%5)*.22).toFixed(2)}s`);
    tile.addEventListener('mouseenter',()=>pulseMitreTrail(tiles,tile));
    tile.addEventListener('focus',()=>pulseMitreTrail(tiles,tile));
  });
  if(prefersReducedMotion())return;
  const starter=[tiles[Math.floor(tiles.length/2)],tiles[0],tiles[tiles.length-1]].filter(Boolean);
  starter.forEach((tile,index)=>{
    const timer=window.setTimeout(()=>{
      mitreKickoffTimers=mitreKickoffTimers.filter(item=>item!==timer);
      pulseMitreTrail(tiles,tile);
    },220+(index*260));
    mitreKickoffTimers.push(timer);
  });
  mitreWaveIndex=Math.floor(tiles.length/3);
  mitreLiveTimer=window.setInterval(()=>{
    const first=tiles[mitreWaveIndex%tiles.length];
    mitreWaveIndex=(mitreWaveIndex+3)%tiles.length;
    pulseMitreTrail(tiles,first);
  },1200);
}

// Dashboard
function dashRiskClass(level=''){
  const rl=String(level||'info').toLowerCase();
  return rl==='critical'?'ac':rl==='high'?'ah':rl==='medium'?'am':'ai';
}

function dashSeverityBadge(level=''){
  const rl=String(level||'info').toLowerCase();
  return rl==='critical'?'sc':rl==='high'?'sh':rl==='medium'?'sm':'sl';
}

function dashTime(value){
  const d=value?new Date(value):new Date();
  if(Number.isNaN(d.getTime()))return 'Just now';
  return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function dashActivityMeta(item={}){
  const text=`${item.title||''} ${item.input_type||''} ${item.kind||''}`.toLowerCase();
  if(/yara|rule matched|apt/.test(text))return {icon:'YR',source:'YARA Scanner',desc:'Uploaded sample matched a project YARA detection rule.'};
  if(/ioc|indicator|ip|domain|enrichment/.test(text))return {icon:'IO',source:'IOC Enrichment',desc:'External intelligence updated for observed network indicators.'};
  if(/upload|file/.test(text))return {icon:'FL',source:'File Analysis',desc:'Uploaded artifact was processed and queued for analyst review.'};
  if(/mitre|credential|technique/.test(text))return {icon:'AT',source:'MITRE Mapping',desc:'Observed behavior was mapped to ATT&CK techniques.'};
  if(/powershell|command|execution/.test(text))return {icon:'PS',source:'Detection Activity',desc:'Command execution behavior requires endpoint validation.'};
  if(/scheduled|persistence|task/.test(text))return {icon:'PR',source:'Persistence Watch',desc:'Persistence-like activity was detected in the investigation stream.'};
  if(/c2|beacon|outbound/.test(text))return {icon:'C2',source:'Network Detection',desc:'Potential command-and-control traffic was observed.'};
  return {icon:'SO',source:item.kind||String(item.input_type||'SOC Activity').replace(/_/g,' '),desc:'SOC Copilot recorded new analyst activity.'};
}

function dashDemoItems(){
  const now=Date.now();
  return [
    {title:'Suspicious PowerShell beacon observed',input_type:'file_analysis',risk_level:'high',risk_score:8.6,created_at:new Date(now-7*60000).toISOString(),analysis_uuid:'demo-psh',demo:true,kind:'File Analysis'},
    {title:'YARA match: APT validation sample',input_type:'yara_scan',risk_level:'critical',risk_score:9.1,created_at:new Date(now-18*60000).toISOString(),analysis_uuid:'demo-yara',demo:true,kind:'YARA Scanner'},
    {title:'IOC enrichment flagged public attacker IP',input_type:'ioc_enrichment',risk_level:'medium',risk_score:6.4,created_at:new Date(now-31*60000).toISOString(),analysis_uuid:'demo-ioc',demo:true,kind:'IOC Enrichment'},
    {title:'MITRE mapping updated: Credential Access',input_type:'investigation',risk_level:'high',risk_score:7.8,created_at:new Date(now-48*60000).toISOString(),analysis_uuid:'demo-mitre',demo:true,kind:'Investigation'}
  ];
}

function dashIntelFromItems(items=[]){
  const text=items.map(item=>[
    item.title,item.input_type,item.threat_type,item.risk_level,
    JSON.stringify(item.iocs||{}),JSON.stringify(item.mitre_techniques||[])
  ].join(' ')).join(' ').toLowerCase();
  const iocs=[
    {type:'IP',value:'45.33.32.156',risk:'high'},
    {type:'DOMAIN',value:'command-gateway.net',risk:'medium'},
    {type:'HASH',value:'b1946ac92492d2347c6235b4d2611184',risk:'info'}
  ];
  const rules=[
    {name:'APT_Static_Beacon_Validation',matches:Math.max(1,items.filter(i=>/yara|apt|malware/i.test(`${i.title} ${i.input_type}`)).length),risk:'high'},
    {name:'Suspicious_PowerShell_Download',matches:Math.max(1,items.filter(i=>/powershell|execution/i.test(i.title||'')).length),risk:'medium'}
  ];
  const ips=[
    {ip:'45.33.32.156',country:'NL',risk:'high'},
    {ip:'185.199.108.133',country:'US',risk:'medium'},
    {ip:'104.21.32.1',country:'Global',risk:'info'}
  ];
  const techniques=[
    {id:'T1059',name:'Command Execution',count:(text.match(/powershell|command|execution/g)||[]).length||4},
    {id:'T1003',name:'Credential Access',count:(text.match(/credential|lsass|dump/g)||[]).length||2},
    {id:'T1071',name:'C2 Protocol',count:(text.match(/c2|beacon|connection/g)||[]).length||3},
    {id:'T1070',name:'Defense Evasion',count:(text.match(/clear|evasion|log/g)||[]).length||1}
  ];
  const riskCounts={critical:0,high:0,medium:0,info:0};
  items.forEach(item=>{
    const key=['critical','high','medium'].includes(String(item.risk_level||'').toLowerCase())?String(item.risk_level).toLowerCase():'info';
    riskCounts[key]+=1;
  });
  return {iocs,rules,ips,techniques,riskCounts};
}

function renderDashActivity(items=[]){
  const list=document.getElementById('rec-list');
  if(!list)return;
  list.innerHTML=items.map(item=>{
    const rl=String(item.risk_level||'info').toLowerCase();
    const cls=dashRiskClass(rl);
    const sev=dashSeverityBadge(rl);
    const meta=dashActivityMeta(item);
    const score=Number(item.risk_score||0);
    const click=item.demo?'':'onclick="viewUUID(\''+escapeHTML(item.analysis_uuid)+'\')"';
    return `<div class="alert-item dash-feed-item ${cls}" ${click}>
      <div class="dash-feed-time">${dashTime(item.created_at)}</div>
      <div class="dash-feed-icon">${escapeHTML(meta.icon)}</div>
      <div class="dash-feed-content">
        <div class="dash-feed-top"><span class="sev ${sev}">${escapeHTML(rl.toUpperCase())}</span><span class="dash-source-label">${escapeHTML(meta.source)}</span></div>
        <div class="al-name">${escapeHTML(item.title||'SOC activity')}</div>
        <div class="dash-feed-desc">${escapeHTML(meta.desc)}</div>
      </div>
      <div class="dash-feed-score">${score?score.toFixed(1):'--'}</div>
    </div>`;
  }).join('');
}

function renderDashWidgetList(title,items,kind){
  return `<div class="card dash-widget dash-widget-${kind}">
    <div class="card-head"><span class="card-title">${escapeHTML(title)}</span><span class="dash-widget-dot"></span></div>
    <div class="card-body dash-widget-body">${items.map(item=>`
      <div class="dash-widget-row">
        <div><strong>${escapeHTML(item.value||item.name||item.ip)}</strong><span>${escapeHTML(item.type||item.country||`${item.matches} match(es)`||'Observed')}</span></div>
        <em class="dash-risk-${escapeHTML(item.risk||'info')}">${escapeHTML(String(item.risk||'active').toUpperCase())}</em>
      </div>`).join('')}</div>
  </div>`;
}

function renderDashBars(title,items,color='cyan'){
  const max=Math.max(...items.map(i=>i.count||0),1);
  return `<div class="card dash-chart-card">
    <div class="card-head"><span class="card-title">${escapeHTML(title)}</span></div>
    <div class="card-body dash-bars">${items.map(item=>`
      <div class="dash-bar-row">
        <span>${escapeHTML(item.id||item.label)}</span>
        <div class="dash-bar-track"><i class="dash-bar-${color}" style="width:${Math.max(8,((item.count||0)/max)*100)}%"></i></div>
        <strong>${item.count||0}</strong>
      </div>`).join('')}</div>
  </div>`;
}

function renderDashDistribution(riskCounts){
  const total=Math.max(Object.values(riskCounts).reduce((a,b)=>a+b,0),1);
  const parts=[
    ['critical',riskCounts.critical||0],
    ['high',riskCounts.high||0],
    ['medium',riskCounts.medium||0],
    ['info',riskCounts.info||0]
  ];
  return `<div class="card dash-chart-card">
    <div class="card-head"><span class="card-title">Severity Distribution</span></div>
    <div class="card-body">
      <div class="dash-donut" style="--crit:${(parts[0][1]/total)*100}%;--high:${(parts[1][1]/total)*100}%;--med:${(parts[2][1]/total)*100}%"><span>${total}</span></div>
      <div class="dash-dist-legend">${parts.map(([label,count])=>`<span class="dash-risk-${label}">${label.toUpperCase()} ${count}</span>`).join('')}</div>
    </div>
  </div>`;
}

function renderDashboardWidgets(items=[]){
  const grid=document.getElementById('dash-widget-grid');
  const charts=document.getElementById('dash-chart-grid');
  if(!grid||!charts)return;
  const intel=dashIntelFromItems(items);
  grid.innerHTML=[
    renderDashWidgetList('Top Detected IOCs',intel.iocs,'iocs'),
    renderDashWidgetList('Top Matched YARA Rules',intel.rules,'yara'),
    renderDashWidgetList('Recent Malicious IPs',intel.ips,'ips'),
    `<div class="card dash-widget">
      <div class="card-head"><span class="card-title">IOC Enrichment Summary</span><span class="dash-widget-dot"></span></div>
      <div class="card-body dash-kpi-stack">
        <div><span>Queued indicators</span><strong>${intel.iocs.length}</strong></div>
        <div><span>High-risk sources</span><strong>${intel.ips.filter(i=>i.risk==='high').length}</strong></div>
        <div><span>Active techniques</span><strong>${intel.techniques.length}</strong></div>
      </div>
    </div>`
  ].join('');
  charts.innerHTML=[
    renderDashBars('Top Attack Techniques',intel.techniques,'cyan'),
    renderDashBars('Detections Over Time',[
      {label:'00:00',count:2},{label:'06:00',count:5},{label:'12:00',count:items.length||4},{label:'18:00',count:Math.max(1,items.length-1)}
    ],'amber'),
    renderDashDistribution(intel.riskCounts)
  ].join('');
}

function updateDashboardMeta(stats){
  const total=stats.total||0;
  const set=(id,text)=>{const el=document.getElementById(id);if(el)el.textContent=text;};
  set('sc-meta',`${stats.critical||0} active / ${(total?((stats.critical||0)/total)*100:0).toFixed(0)}% of queue`);
  set('sh-meta',`${stats.high||0} priority investigations`);
  set('sm-meta',`${stats.medium||0} monitored signals`);
  set('st-meta',`${total} total records indexed`);
}

async function loadDash(){
  try{
    const s=await apiFetch('/api/v1/analysis/stats');
    const b=s.stats?.by_risk_level||{};
    const dashStats={
      critical:b.critical||0,
      high:b.high||0,
      medium:b.medium||0,
      total:s.stats?.total||0
    };
    animateDashboardCounters(dashStats);
    updateDashboardMeta(dashStats);
    const h=await apiFetch('/api/v1/analysis/history?page_size=12');
    const liveItems=h.items||[];
    const items=liveItems.length?liveItems:dashDemoItems();
    const recentBadge=document.getElementById('rec-cnt');
    recentBadge.textContent=(liveItems.length?items.length:'DEMO')+' RECENT';
    pulseBadge(recentBadge);
    renderDashActivity(items);
    renderDashboardWidgets(items);
    animateRecentList();
  }catch(e){notify('Dashboard error: '+e.message,'err');}
  buildMitre();
  replayDashboardMotion();
}

function buildMitre(){
  const g=document.getElementById('mitre-grid');
  const rows=[
    [
      {id:'T1566',code:'PHI',n:'Phishing',l:1},
      {id:'T1190',code:'EXP',n:'Exploit Public App',l:1},
      {id:'T1078',code:'VAC',n:'Valid Accounts',l:2},
      {id:'T1204',code:'USR',n:'User Execution',l:2}
    ],
    [
      {id:'T1059',code:'PSH',n:'PowerShell',l:2},
      {id:'T1021',code:'LAT',n:'Remote Services',l:2},
      {id:'T1053',code:'SCH',n:'Scheduled Task',l:2},
      {id:'T1105',code:'ING',n:'Ingress Tool Transfer',l:2},
      {id:'T1016',code:'NET',n:'Network Discovery',l:1}
    ],
    [
      {id:'T1110',code:'BRT',n:'Brute Force',l:2},
      {id:'T1003',code:'CRD',n:'Credential Dumping',l:3},
      {id:'T1071',code:'C2C',n:'Application Layer Protocol',l:3},
      {id:'T1055',code:'INJ',n:'Process Injection',l:3},
      {id:'T1041',code:'EXF',n:'Exfiltration Over C2',l:3},
      {id:'T1047',code:'WMI',n:'Windows Management Instrumentation',l:1},
      {id:'T1018',code:'REM',n:'Remote System Discovery',l:1}
    ],
    [
      {id:'T1547',code:'AUT',n:'Autostart Execution',l:2},
      {id:'T1543',code:'SVC',n:'Create Service',l:2},
      {id:'T1218',code:'SIG',n:'Signed Binary Proxy',l:2},
      {id:'T1087',code:'ACD',n:'Account Discovery',l:1},
      {id:'T1497',code:'SBX',n:'Sandbox Evasion',l:2}
    ],
    [
      {id:'T1112',code:'REG',n:'Modify Registry',l:2},
      {id:'T1036',code:'MSQ',n:'Masquerading',l:2},
      {id:'T1070',code:'CLR',n:'Indicator Removal',l:3},
      {id:'T1486',code:'ENC',n:'Data Encrypted For Impact',l:3}
    ]
  ];
  const rowShift=['0px','34px','0px','34px','0px'];
  const totalTechniques=rows.reduce((sum,row)=>sum+row.length,0);
  const activeTechniques=rows.flat().filter(t=>t.l>=2).length;
  const highTechniques=rows.flat().filter(t=>t.l>=3).length;
  const mitreSummary=document.getElementById('dash-mitre-summary');
  if(mitreSummary){
    mitreSummary.innerHTML=`
      <div><span>Tracked Techniques</span><strong>${totalTechniques}</strong></div>
      <div><span>Active Highlights</span><strong>${activeTechniques}</strong></div>
      <div><span>High Confidence</span><strong>${highTechniques}</strong></div>
    `;
  }
  const topTechniques=[
    {id:'T1059',name:'PowerShell',count:8,confidence:'92%'},
    {id:'T1071',name:'Command and Control',count:7,confidence:'88%'},
    {id:'T1003',name:'Credential Access',count:6,confidence:'85%'}
  ];
  const topBox=document.getElementById('dash-top-techniques');
  if(topBox){
    topBox.innerHTML=`<div class="dash-top-title">Top Techniques</div>${topTechniques.map(t=>`
      <a class="dash-tech-row" href="https://attack.mitre.org/techniques/${t.id}/" target="_blank" rel="noreferrer" title="${t.id} - ${t.name}">
        <strong>${t.id}</strong>
        <span>${escapeHTML(t.name)}</span>
        <em>${t.count} seen / ${t.confidence}</em>
      </a>
    `).join('')}`;
  }
  g.innerHTML=rows.map((row,index)=>`
    <div class="mitre-row" style="--row-shift:${rowShift[index]||'0px'}">
      ${row.map((t,tileIndex)=>{
        const seen=(t.l*2)+tileIndex;
        const confidence=Math.min(96,62+(t.l*9)+(tileIndex*2));
        return `<a class="mc ml${t.l}" href="https://attack.mitre.org/techniques/${t.id}/" target="_blank" rel="noreferrer" title="${t.id} - ${t.n} | Seen: ${seen} | Confidence: ${confidence}%" data-row="${index}" data-col="${tileIndex}" data-count="${seen}" data-confidence="${confidence}" style="--tile-delay:${((index*6)+tileIndex)*58}ms">
        <span class="mcore"></span>
        <div class="tid">${t.code}</div>
        <div class="tsub">${t.id.replace('T','')}</div>
        <div class="tn">${t.n}</div>
        <div class="tcount">${seen}</div>
      </a>`;
      }).join('')}
    </div>
  `).join('');
  wireMitreMotion();
}

// Analyzer
function setType(btn,t){document.querySelectorAll('.type-row .tbtn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');aType=t;}

async function analyzeAlert(){
  const text=document.getElementById('alert-input').value.trim();
  if(!text){notify('Enter alert text','err');return;}
  const pid=document.getElementById('proj-id').value||'1';
  const btn=document.getElementById('an-btn');
  document.getElementById('an-sp').style.display='inline-block';
  btn.disabled=true;document.getElementById('an-loading').classList.add('show');
  try{
    const d=await apiFetch(`/api/v1/analysis/alert/${pid}`,{method:'POST',body:JSON.stringify({alert_text:text,input_type:aType})});
    const a=d.analysis?.analysis_result||d.analysis||{};
    curUUID=d.analysis_uuid||d.analysis?.analysis_uuid;
    renderResult(a,curUUID);
    document.getElementById('feedback-row').style.display='block';
    notify('Analysis complete!','ok');
  }catch(e){notify('Analysis failed: '+e.message,'err');}
  finally{document.getElementById('an-sp').style.display='none';btn.disabled=false;document.getElementById('an-loading').classList.remove('show');}
}

function renderResult(a,uuid){
  const sev=a.severity||{};
  const score=sev.score||0,level=(sev.level||'info').toUpperCase(),conf=sev.confidence||0;
  const rcolor=level==='CRITICAL'?'var(--red)':level==='HIGH'?'var(--orange)':level==='MEDIUM'?'var(--yellow)':'var(--green)';
  document.getElementById('r-uuid').textContent=uuid?uuid.substring(0,8)+'...':'-';
  document.getElementById('r-score').textContent=score.toFixed(1);document.getElementById('r-score').style.color=rcolor;
  document.getElementById('r-level').textContent=level;document.getElementById('r-level').style.color=rcolor;
  document.getElementById('r-bar').style.width=(score*10)+'%';
  document.getElementById('r-conf').textContent=`Confidence: ${(conf*100).toFixed(0)}% - ${a.threat_type||'Unknown'}`;
  document.getElementById('r-summary').textContent=a.summary||'No summary';document.getElementById('r-summary').style.color='var(--text2)';
  const techs=a.mitre_techniques||[];
  document.getElementById('r-mitre').innerHTML=techs.map(t=>`<a class="tag tp mitre-tag-link" href="https://attack.mitre.org/techniques/${t.technique_id}/" target="_blank" rel="noreferrer">${t.technique_id} - ${t.technique_name||''}</a>`).join('')||'<span style="color:var(--text3);font-size:10px;">None identified</span>';
  document.getElementById('r-iocs').innerHTML=renderIOCMarkup(a.iocs||{},{sourceKey:'alert-analysis'});
  document.getElementById('r-rules').innerHTML=renderRuleMarkup(a.detection_rules||{});
  const acts=a.recommended_actions||[];
  document.getElementById('r-actions').innerHTML=acts.map(ac=>{const pc=ac.priority===1?'ap1':ac.priority===2?'ap2':'ap3';return`<div class="action-item"><span class="ap ${pc}">[P${ac.priority}]</span><span>${ac.action}: ${ac.description||''}</span></div>`;}).join('')||'<span style="color:var(--text3);font-size:10px;">No actions</span>';
}

async function sendFeedback(fb){
  if(!curUUID){notify('No analysis to rate','err');return;}
  try{
    await apiFetch(`/api/v1/analysis/history/${curUUID}/feedback`,{method:'PATCH',body:JSON.stringify({feedback:fb,notes:''})});
    notify('Feedback submitted: '+fb,'ok');
  }catch(e){notify('Feedback error: '+e.message,'err');}
}

// File Analysis
const ATTACK_STAGE_RULES=[
  {stage:'Failed login / brute force',severity:'high',patterns:[/\b4625\b/i,/\bfailed\s+(?:login|logon|password|authentication|auth)\b/i,/\b(?:login|logon|authentication|auth)\s+failed\b/i,/\bauthentication failure\b/i,/\binvalid user\b/i,/\bbrute\s*force\b/i,/\bpassword spray(?:ing)?\b/i,/\bfailurecount\s*=\s*[2-9]\d*\b/i,/\bmultiple\s+failed\b/i]},
  {stage:'Successful login',severity:'medium',patterns:[/\b4624\b/i,/\bsuccess(?:ful|fully)?\s+(?:login|logon|authentication|auth)\b/i,/\b(?:login|logon|authentication|auth)\s+success(?:ful|fully)?\b/i,/\baccepted password\b/i,/\blogon type\b/i,/\bsession established\b/i]},
  {stage:'PowerShell or command execution',severity:'high',patterns:[/\b4688\b/i,/\bpowershell(?:\.exe)?\b/i,/\bpwsh(?:\.exe)?\b/i,/\bcmd(?:\.exe)?\b/i,/\b(?:wscript|cscript|rundll32|regsvr32|mshta)(?:\.exe)?\b/i,/\bprocess creation\b/i,/\bcommand\s*line\b/i,/\bcommand execution\b/i,/\bencodedcommand\b/i,/\bexec(?:ute|uted|ution)?\b/i]},
  {stage:'Credential Access',severity:'critical',patterns:[/\bT1003(?:\.\d+)?\b/i,/\blsass(?:\.exe)?\b/i,/\bcredential(?:s)?\s+(?:dump|dumping|access|theft|harvest)/i,/\bdump(?:ed|ing)?\s+(?:creds|credentials|tokens|lsass|sam)\b/i,/\bmimikatz\b/i,/\bsekurlsa\b/i,/\bprocdump\b.*\blsass\b/i,/\bcomsvcs\.dll\b.*\bMiniDump\b/i,/\bSAM\b.*\b(?:access|dump|save|copy)\b/i,/\bntds\.dit\b/i,/\btoken\s+(?:dump|theft|impersonation)\b/i]},
  {stage:'Account creation / privilege escalation',severity:'critical',patterns:[/\b4720\b/i,/\b4728\b/i,/\b4732\b/i,/\b4672\b/i,/\bnew user account\b/i,/\baccount creation\b/i,/\baccount created\b/i,/\bcreated\s+(?:user|account)\b/i,/\bnet user\b.*\b\/add\b/i,/\buseradd\b/i,/\badduser\b/i,/\b(?:added|add)\b.*\b(?:administrators|domain admins|sudoers|admin group)\b/i,/\blocalgroup administrators\b.*\b\/add\b/i,/\bprivilege escalation\b/i,/\bescalat(?:e|ed|ion)\b/i,/\bsudo\b/i]},
  {stage:'Scheduled task persistence',severity:'high',patterns:[/\b4698\b/i,/\bschtasks(?:\.exe)?\b/i,/\bscheduled task\b/i,/\btask scheduler\b/i,/\bpersistence\b/i,/\bcrontab\b/i,/\bcron\s+job\b/i,/\bat\.exe\b/i]},
  {stage:'Outbound network connection / C2',severity:'critical',patterns:[/\b(?:c2|c&c|command and control)\b/i,/\bbeacon(?:ing)?\b/i,/\boutbound (?:connection|traffic|network)\b/i,/\bnetwork connection\b/i,/\bconnected\s+to\b/i,/\bconnection\s+to\b/i,/\bdestination(?:ip|_ip| ip| address)?\b/i,/\bdst(?:ip|_ip| ip)?\b/i,/\b(?:curl|wget)\b.*\b(?:https?|hxxps?):\/\//i,/\b(?:tcp|udp)\b.*\b(?:connect|connection)\b/i,/\bEventCode=3\b/i]},
  {stage:'Data staging / exfiltration',severity:'critical',patterns:[/\bexfil(?:tration|trate|trated)?\b/i,/\bdata staging\b/i,/\bstag(?:e|ed|ing)\b.*\b(?:data|files|archive)\b/i,/\bcollect(?:ed|ing)?\b.*\b(?:data|files|documents)\b/i,/\bcompress-archive\b/i,/\barchive(?:d)?\b.*\b(?:data|files)\b/i,/\b(?:7z|rar|zip)(?:\.exe)?\b/i,/\brclone\b/i,/\bscp\b/i,/\bftp\b/i,/\baws\s+s3\s+cp\b/i,/\bupload(?:ed|ing)?\b.*\b(?:archive|data|files)\b/i]},
  {stage:'Log clearing / defense evasion',severity:'critical',patterns:[/\b1102\b/i,/\bEventCode=104\b/i,/\bwevtutil\b.*\bcl\b/i,/\bclear-eventlog\b/i,/\baudit log cleared\b/i,/\bsecurity log cleared\b/i,/\blog clearing\b/i,/\blog(?:s)? (?:cleared|deleted|wiped)\b/i,/\bcleared\b.*\blog(?:s)?\b/i,/\bdefense evasion\b/i,/\bdisable(?:d)?\b.*\b(?:defender|logging|audit)\b/i]}
];

const TIMESTAMP_PATTERNS=[
  /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/,
  /\b\d{1,2}\/\d{1,2}\/\d{4}[ T]\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?\b/i,
  /\b\d{1,2}-\d{1,2}-\d{4}[ T]\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?\b/i,
  /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/i
];

function resetAttackTimeline(message='Upload and analyze a TXT or LOG file to build a chronological attack timeline.'){
  const body=document.getElementById('attack-timeline');
  const count=document.getElementById('attack-timeline-count');
  lastAttackTimelineEvents=[];
  if(count)count.textContent='0';
  if(body)body.innerHTML=`<div class="attack-timeline-empty">${escapeHTML(message)}</div>`;
}

function extractLogTimestamp(line,index){
  for(const pattern of TIMESTAMP_PATTERNS){
    const match=String(line||'').match(pattern);
    if(!match)continue;
    let raw=match[0];
    let normalized=/^\d{4}-\d{2}-\d{2}/.test(raw)?raw.replace(' ','T'):raw;
    if(/^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/i.test(raw)){
      normalized=`${new Date().getFullYear()} ${raw}`;
    }
    const parsed=Date.parse(normalized);
    return {label:raw,sort:Number.isNaN(parsed)?Number.MAX_SAFE_INTEGER+index:parsed};
  }
  return {label:'No timestamp',sort:Number.MAX_SAFE_INTEGER+index};
}

function detectAttackStage(line){
  const text=String(line||'');
  const normalized=text.replace(/[_=-]+/g,' ');
  for(const rule of ATTACK_STAGE_RULES){
    if(rule.patterns.some(pattern=>pattern.test(text)||pattern.test(normalized)))return {stage:rule.stage,severity:rule.severity};
  }
  return null;
}

function parseAttackTimeline(logText=''){
  const lines=String(logText||'').split(/\r?\n/);
  const events=[];
  lines.slice(0,10000).forEach((line,index)=>{
    const trimmed=line.trim();
    if(!trimmed)return;
    const match=detectAttackStage(trimmed);
    if(!match)return;
    const timestamp=extractLogTimestamp(trimmed,index);
    events.push({line:trimmed,timestamp:timestamp.label,sort:timestamp.sort,stage:match.stage,severity:match.severity,index});
  });
  return events.sort((a,b)=>a.sort-b.sort||a.index-b.index);
}

function renderAttackTimeline(events=[]){
  const body=document.getElementById('attack-timeline');
  const count=document.getElementById('attack-timeline-count');
  lastAttackTimelineEvents=Array.isArray(events)?events:[];
  if(count)count.textContent=String(events.length);
  if(!body)return;
  if(!events.length){
    resetAttackTimeline('No attack timeline events were detected in the uploaded log lines.');
    return;
  }
  const rows=events.slice(0,75).map(event=>`
    <div class="attack-timeline-item sev-${event.severity}">
      <div class="attack-timeline-marker"></div>
      <div class="attack-timeline-content">
        <div class="attack-timeline-meta">
          <span class="attack-timeline-time">${escapeHTML(event.timestamp)}</span>
          <span class="attack-timeline-stage">${escapeHTML(event.stage)}</span>
          <span class="attack-timeline-severity">${escapeHTML(event.severity.toUpperCase())}</span>
        </div>
        <div class="attack-timeline-log">${escapeHTML(event.line)}</div>
      </div>
    </div>`).join('');
  const clipped=events.length>75?`<div class="attack-timeline-note">Showing first 75 of ${events.length} detected timeline events.</div>`:'';
  body.innerHTML=`<div class="attack-timeline-list">${rows}</div>${clipped}`;
}

function readTimelineFileText(file){
  if(!file)return Promise.resolve('');
  if(typeof file.text==='function')return file.text();
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onload=()=>resolve(String(reader.result||''));
    reader.onerror=()=>reject(reader.error||new Error('File read failed'));
    reader.readAsText(file);
  });
}

async function buildAttackTimelineFromFile(file,textPromise=null){
  if(!file){resetAttackTimeline();return;}
  const name=file.name||'';
  if(!/\.(?:txt|log)$/i.test(name)){
    resetAttackTimeline('Timeline parsing is available for TXT and LOG uploads.');
    return;
  }
  try{
    resetAttackTimeline('Parsing uploaded log lines...');
    const text=textPromise?await textPromise:await readTimelineFileText(file);
    renderAttackTimeline(parseAttackTimeline(text));
  }catch(e){
    resetAttackTimeline(`Could not parse timeline: ${e.message}`);
  }
}

async function buildAttackTimelineFromSelectedFile(){
  return buildAttackTimelineFromFile(selFile);
}

const AUTO_INV_STAGE_ORDER=[
  'Initial Access',
  'Execution',
  'Credential Access',
  'Privilege Escalation',
  'Persistence',
  'Command & Control',
  'Exfiltration',
  'Defense Evasion'
];

const AUTO_INV_STAGE_META={
  'Initial Access':{tone:'ia',severity:'high',mitre:['T1110','T1078']},
  'Execution':{tone:'ex',severity:'high',mitre:['T1059','T1059.001']},
  'Credential Access':{tone:'di',severity:'critical',mitre:['T1003','T1003.001']},
  'Privilege Escalation':{tone:'pe',severity:'critical',mitre:['T1068','T1136']},
  'Persistence':{tone:'pe',severity:'high',mitre:['T1053','T1053.005']},
  'Command & Control':{tone:'la',severity:'critical',mitre:['T1071','T1105']},
  'Exfiltration':{tone:'di',severity:'critical',mitre:['T1041','T1567']},
  'Defense Evasion':{tone:'di',severity:'critical',mitre:['T1070','T1070.001']},
};

function autoInvStageFromTimelineStage(stage=''){
  const text=String(stage||'').toLowerCase();
  if(/failed login|brute force|successful login/.test(text))return 'Initial Access';
  if(/powershell|command execution|process/.test(text))return 'Execution';
  if(/credential access|lsass|credential|mimikatz|sam|token|t1003/.test(text))return 'Credential Access';
  if(/account creation|privilege escalation/.test(text))return 'Privilege Escalation';
  if(/scheduled task|persistence/.test(text))return 'Persistence';
  if(/outbound|c2|command.*control|network connection/.test(text))return 'Command & Control';
  if(/data staging|exfil/.test(text))return 'Exfiltration';
  if(/log clearing|defense evasion/.test(text))return 'Defense Evasion';
  return 'Execution';
}

function severityRank(level=''){
  return {critical:4,high:3,medium:2,low:1,info:0}[String(level||'info').toLowerCase()]||0;
}

function strongestSeverity(events=[]){
  return events.reduce((best,event)=>severityRank(event.severity)>severityRank(best)?event.severity:best,'info');
}

function mitreTagsForAutoStage(stage,analysis={}){
  const defaults=AUTO_INV_STAGE_META[stage]?.mitre||[];
  const techs=analysis.mitre_techniques||[];
  const haystack=stage.toLowerCase();
  const matched=techs.filter(t=>{
    const name=String(t.technique_name||'').toLowerCase();
    const id=String(t.technique_id||'');
    return defaults.some(tag=>id.startsWith(tag))||name.includes(haystack.split(' ')[0]);
  }).map(t=>t.technique_id||t.technique_name).filter(Boolean);
  return [...new Set([...matched,...defaults])].slice(0,4);
}

function buildAutoInvestigationStages(timelineEvents=[],analysis={}){
  const grouped=AUTO_INV_STAGE_ORDER.map(stage=>({stage,events:[],meta:AUTO_INV_STAGE_META[stage]}));
  const byStage=Object.fromEntries(grouped.map(item=>[item.stage,item]));
  timelineEvents.forEach(event=>{
    const stage=autoInvStageFromTimelineStage(event.stage);
    byStage[stage]?.events.push(event);
  });
  return grouped.filter(item=>item.events.length).map(item=>({
    ...item,
    severity:strongestSeverity(item.events)||item.meta.severity,
    mitre:mitreTagsForAutoStage(item.stage,analysis)
  }));
}

function autoInvestigationStory(stages=[]){
  if(!stages.length)return 'No correlated attack stages were detected from the analyzed log.';
  const names=stages.map(item=>item.stage);
  return `SOC Copilot correlated ${stages.reduce((sum,item)=>sum+item.events.length,0)} timeline event(s) across ${names.length} stage(s): ${names.join(' -> ')}. Review the ordered flow below and use Investigate for backend-assisted enrichment if needed.`;
}

function sigmaYamlValues(values=[],limit=6){
  const seen=new Set();
  return values.filter(Boolean).map(value=>String(value).trim()).filter(value=>{
    const key=value.toLowerCase();
    if(!value||seen.has(key))return false;
    seen.add(key);
    return true;
  }).slice(0,limit).map(value=>`      - '${value.replace(/'/g,"''")}'`).join('\n');
}

function buildAutoSigmaDetectionRule(analysis={},timelineEvents=[]){
  const normalized=normalizeDetectionRules(analysis.detection_rules||{});
  if(normalized.sigma_rule)return formatRuleCode(normalized.sigma_rule);

  const iocs=analysis.iocs||{};
  const selections=[];
  const conditions=[];
  const rawLines=timelineEvents.map(event=>String(event.line||''));
  const rawText=rawLines.join('\n');
  const processes=[
    ...valuesFromIOCGroup(iocs,'processes'),
    ...(rawText.match(/\b[A-Za-z0-9._-]+\.exe\b/gi)||[])
  ];
  const ips=[
    ...valuesFromIOCGroup(iocs,'ip_addresses'),
    ...(rawText.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[])
  ].filter(isPublicIP);
  const domains=[
    ...valuesFromIOCGroup(iocs,'domains'),
    ...(rawText.match(/\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b/g)||[])
  ].filter(isValidDomain);
  const commandHints=[];
  timelineEvents.forEach(event=>{
    const line=String(event.line||'').toLowerCase();
    if(line.includes('powershell')&&line.includes('-enc'))commandHints.push('-enc');
    if(line.includes('vssadmin')&&line.includes('delete shadows'))commandHints.push('delete shadows');
    if(line.includes('lsass'))commandHints.push('lsass');
    if(line.includes('scheduled task')||line.includes('task scheduler'))commandHints.push('schtasks');
    if(line.includes('beacon'))commandHints.push('beacon');
  });
  if(!commandHints.length&&timelineEvents.length){
    commandHints.push('powershell','vssadmin','lsass','scheduled task','beacon');
  }

  const processValues=sigmaYamlValues(processes);
  if(processValues){selections.push(`  selection_process:\n    Image|endswith:\n${processValues}`);conditions.push('selection_process');}
  const commandValues=sigmaYamlValues(commandHints);
  if(commandValues){selections.push(`  selection_command:\n    CommandLine|contains:\n${commandValues}`);conditions.push('selection_command');}
  const ipValues=sigmaYamlValues(ips);
  if(ipValues){selections.push(`  selection_ip:\n    DestinationIp|contains:\n${ipValues}`);conditions.push('selection_ip');}
  const domainValues=sigmaYamlValues(domains);
  if(domainValues){selections.push(`  selection_domain:\n    DestinationHostname|contains:\n${domainValues}`);conditions.push('selection_domain');}
  if(!selections.length)return '';

  return [
    'title: Similar Attack Chain Detection',
    'id: soc-copilot-auto-investigation-similar-attack',
    'status: experimental',
    'description: Detects activity similar to the uploaded log investigation chain using observed process, command, and network patterns.',
    'logsource:',
    '  product: windows',
    'detection:',
    selections.join('\n'),
    `  condition: ${conditions.join(' or ')}`,
    'fields:',
    '  - Image',
    '  - CommandLine',
    '  - DestinationIp',
    '  - DestinationHostname',
    'falsepositives:',
    '  - Authorized administration or testing activity matching the same patterns.',
    'level: high'
  ].join('\n');
}

function renderAutoSigmaDetectionRules(analysis={},timelineEvents=[]){
  const sigma=buildAutoSigmaDetectionRule(analysis,timelineEvents);
  if(!sigma)return '';
  return `<div class="auto-sigma-section">
    <div class="inv-section-title">Sigma Rules</div>
    ${renderRuleBlock('SIGMA RULES - SIMILAR ATTACK DETECTION',sigma,'sigma',{
      sourceRules:{sigma_rule:sigma},
      note:'Detection: convert this Sigma rule to your SIEM or EDR to detect attacks with similar process, command, credential access, persistence, C2, or ransomware impact behavior.'
    })}
  </div>`;
}

function renderAutoInvestigationFlow(timelineEvents=[],analysis={}){
  const content=document.getElementById('chain-content');
  if(!content)return;
  const stages=buildAutoInvestigationStages(timelineEvents,analysis);
  invAutoCorrelated=stages.length>0;
  if(!stages.length){
    document.getElementById('chain-sev').textContent='-';
    content.innerHTML='<div style="padding:30px;text-align:center;color:var(--text3);font-size:11px;">No attack events were detected for auto-correlation.</div>';
    return;
  }
  const overall=strongestSeverity(timelineEvents);
  document.getElementById('chain-sev').textContent=`${String(overall||'info').toUpperCase()} - AUTO`;
  const source=escapeHTML(lastUploadedProjectFile?.fileName||selFile?.name||'analyzed log');
  let html=`<div class="auto-chain-header">
      <div>
        <div class="auto-chain-title">Auto-Correlated Attack Story</div>
        <div class="auto-chain-subtitle">Generated from analyzed log and mapped to investigation stages</div>
      </div>
      <div class="auto-corr-label">Auto-correlated from analyzed log</div>
    </div>
    <div class="story-box auto-story-box"><div class="story-label">ATTACK STORY</div><div class="story-text">${escapeHTML(autoInvestigationStory(stages))}<br><span class="auto-source">Source: ${source}</span></div></div>
    <div class="auto-flow">`;
  stages.forEach((stage,index)=>{
    const meta=stage.meta||{};
    const first=stage.events[0]||{};
    const last=stage.events[stage.events.length-1]||first;
    const mitre=stage.mitre.map(tag=>`<span class="auto-mitre-tag">${escapeHTML(tag)}</span>`).join('');
    const eventRows=stage.events.slice(0,4).map(event=>`
      <div class="auto-event-row">
        <span>${escapeHTML(event.timestamp)}</span>
        <strong>${escapeHTML(event.stage)}</strong>
        <em>${escapeHTML(event.line)}</em>
      </div>`).join('');
    const more=stage.events.length>4?`<div class="auto-more">+ ${stage.events.length-4} more event(s)</div>`:'';
    html+=`<div class="auto-flow-step sev-${escapeHTML(stage.severity)}" style="--stage-index:${index}">
      <div class="chain-dot d-${meta.tone||'ex'}">${index+1}</div>
      <div class="auto-flow-card">
        <div class="auto-flow-head">
          <div>
            <div class="auto-stage-name">${escapeHTML(stage.stage)}</div>
            <div class="auto-stage-time">${escapeHTML(first.timestamp)}${last.timestamp!==first.timestamp?` -> ${escapeHTML(last.timestamp)}`:''}</div>
          </div>
          <span class="auto-sev">${escapeHTML(String(stage.severity||'info').toUpperCase())}</span>
        </div>
        <div class="auto-mitre-row">${mitre||'<span class="auto-mitre-tag muted">No MITRE tag</span>'}</div>
        <div class="auto-event-list">${eventRows}${more}</div>
      </div>
    </div>`;
  });
  html+='</div>';
  html+=renderAutoSigmaDetectionRules(analysis,timelineEvents);
  content.innerHTML=html;
}

function populateInvestigationFromFileAnalysis(){
  if(!lastAttackTimelineEvents.length||!lastFileAnalysisResult)return;
  events=lastAttackTimelineEvents.map(event=>event.line);
  renderEvs();
  renderAutoInvestigationFlow(lastAttackTimelineEvents,lastFileAnalysisResult);
}

function incidentReportTitle(analysis={}){
  const sev=(analysis.severity?.level||'info').toUpperCase();
  const type=analysis.threat_type||analysis.attack_type||analysis.category||'Security Event';
  const fileName=cleanIncidentFileName(lastUploadedProjectFile?.fileName||selFile?.name||'Uploaded File',{stripExtension:true});
  return `${sev} ${type} - ${fileName}`;
}

function cleanIncidentFileName(name='',options={}){
  let value=String(name||'Uploaded file').trim()||'Uploaded file';
  value=value.replace(/(\.[A-Za-z0-9]+)(?:\1)+$/i,'$1');
  value=value.replace(/\.txt\.txt$/i,'.txt');
  if(options.stripExtension)value=value.replace(/\.[^.]+$/,'');
  return value;
}

function incidentSourceFileName(){
  return cleanIncidentFileName(lastUploadedProjectFile?.fileName||selFile?.name||'Uploaded file');
}

function formatIncidentTimeline(events=[]){
  if(!events.length)return '- No attack timeline events were detected in the uploaded log lines.';
  return events.map((event,index)=>[
    `${index+1}. ${event.timestamp}`,
    `   Stage: ${event.stage}`,
    `   Severity: ${event.severity.toUpperCase()}`,
    `   Log: ${event.line}`
  ].join('\n')).join('\n\n');
}

function formatIncidentMitre(analysis={}){
  const techs=analysis.mitre_techniques||[];
  if(!techs.length)return '- None identified';
  return techs.map(t=>`- ${t.technique_id||'Technique'}${t.technique_name?` - ${t.technique_name}`:''}`).join('\n');
}

function formatIncidentIOCs(analysis={}){
  const items=getIncidentIOCs(analysis);
  if(!items.length)return '- No IOCs extracted';
  return items.map(item=>`- [${item.label}] ${item.value}`).join('\n');
}

function getIncidentIOCs(analysis={}){
  const genericValues=new Set(['account','user','users','event','events','log','logs','file','files','process','processes','host','hostname','computer','system','unknown','none','null','na','n/a']);
  return flattenIOCs(analysis.iocs||{}).filter(item=>{
    const normalized=String(item.value||'').trim().toLowerCase();
    const compact=normalized.replace(/[^a-z0-9]+/g,'');
    if(!normalized||genericValues.has(normalized)||genericValues.has(compact))return false;
    if(item.type==='user'&&(/^(?:user|account|admin|administrator)$/i.test(normalized)))return false;
    return true;
  });
}

function incidentClassification(analysis={}){
  const parts=[
    analysis.threat_type||analysis.attack_type||analysis.category||'Security Event',
    analysis.incident_type||analysis.input_type||'File Analysis'
  ].filter(Boolean);
  return [...new Set(parts)].join(' / ');
}

function formatIncidentRules(analysis={}){
  const rules=normalizeDetectionRules(analysis.detection_rules||{});
  const blocks=[
    ['SIGMA',rules.sigma_rule],
    ['SPLUNK SPL',rules.splunk_spl],
    ['ELK QUERY',rules.elk_query],
    ['SURICATA',rules.suricata_rule],
    ['YARA',rules.yara_rule]
  ].filter(([,value])=>value);
  if(!blocks.length)return '- No detection rules generated';
  return blocks.map(([label,value])=>`${label}\n${formatRuleCode(value)}`).join('\n\n');
}

function formatIncidentActions(analysis={}){
  const actions=analysis.recommended_actions||[];
  if(!actions.length)return '- No recommended actions provided';
  return actions.map(action=>`- [P${action.priority||3}] ${action.action||'Response action'}${action.description?`: ${action.description}`:''}`).join('\n');
}

function buildIncidentReportText(){
  if(!lastFileAnalysisResult)return 'Analyze a file first to generate an incident report.';
  const analysis=lastFileAnalysisResult;
  const sev=analysis.severity||{};
  const score=Number(sev.score||0);
  const level=(sev.level||'info').toUpperCase();
  const confidence=Number(sev.confidence||0);
  const generatedAt=new Date().toLocaleString();
  return [
    'SOC COPILOT INCIDENT REPORT',
    `Generated: ${generatedAt}`,
    `Source File: ${incidentSourceFileName()}`,
    '',
    '1. Incident Title',
    incidentReportTitle(analysis),
    '',
    '2. Executive Summary',
    analysis.summary||'No executive summary was generated.',
    '',
    '3. Incident Classification',
    incidentClassification(analysis),
    '',
    '4. Risk Score, Severity, and Confidence',
    `Risk Score: ${score.toFixed(1)}`,
    `Severity: ${level}`,
    `Confidence: ${(confidence*100).toFixed(0)}%`,
    '',
    '5. Attack Timeline',
    formatIncidentTimeline(lastAttackTimelineEvents),
    '',
    '6. MITRE ATT&CK Techniques',
    formatIncidentMitre(analysis),
    '',
    '7. Extracted IOCs',
    formatIncidentIOCs(analysis),
    '',
    '8. Detection Rules',
    formatIncidentRules(analysis),
    '',
    '9. Recommended Response Actions',
    formatIncidentActions(analysis),
    '',
    '10. Analyst Notes',
    '- Add containment decisions, validation notes, affected assets, ticket references, and follow-up owners here.',
    '',
    'Generated by SOC Copilot'
  ].join('\n');
}

function htmlLineBreaks(value=''){
  return escapeHTML(value).replace(/\n/g,'<br>');
}

function incidentSeverityClass(level=''){
  const l=String(level||'info').toLowerCase();
  return ['critical','high','medium','low'].includes(l)?l:'info';
}

function buildIncidentReportHtml(){
  if(!lastFileAnalysisResult)return '';
  const analysis=lastFileAnalysisResult;
  const sev=analysis.severity||{};
  const score=Number(sev.score||0);
  const level=(sev.level||'info').toUpperCase();
  const confidence=Number(sev.confidence||0);
  const generatedAt=new Date().toLocaleString();
  const iocs=getIncidentIOCs(analysis);
  const mitre=analysis.mitre_techniques||[];
  const actions=analysis.recommended_actions||[];
  const rules=normalizeDetectionRules(analysis.detection_rules||{});
  const ruleBlocks=[
    ['SIGMA',rules.sigma_rule],
    ['SPLUNK SPL',rules.splunk_spl],
    ['ELK QUERY',rules.elk_query],
    ['SURICATA',rules.suricata_rule],
    ['YARA',rules.yara_rule]
  ].filter(([,value])=>value);
  const timelineRows=lastAttackTimelineEvents.length?lastAttackTimelineEvents.map((event,index)=>`
    <tr>
      <td>${index+1}</td>
      <td>${escapeHTML(event.timestamp)}</td>
      <td>${escapeHTML(event.stage)}</td>
      <td><span class="pdf-badge ${incidentSeverityClass(event.severity)}">${escapeHTML(String(event.severity||'info').toUpperCase())}</span></td>
      <td>${escapeHTML(event.line)}</td>
    </tr>`).join(''):`<tr><td colspan="5">No attack timeline events were detected in the uploaded log lines.</td></tr>`;
  const iocRows=iocs.length?iocs.map(item=>`
    <tr>
      <td>${escapeHTML(item.label)}</td>
      <td>${escapeHTML(item.bucket||item.type||'IOC')}</td>
      <td>${escapeHTML(item.value)}</td>
    </tr>`).join(''):`<tr><td colspan="3">No IOCs extracted after generic value filtering.</td></tr>`;
  const mitreRows=mitre.length?mitre.map(t=>`
    <tr>
      <td>${escapeHTML(t.technique_id||'Technique')}</td>
      <td>${escapeHTML(t.technique_name||'')}</td>
    </tr>`).join(''):`<tr><td colspan="2">None identified.</td></tr>`;
  const actionRows=actions.length?actions.map(action=>`
    <tr>
      <td>P${escapeHTML(action.priority||3)}</td>
      <td>${escapeHTML(action.action||'Response action')}</td>
      <td>${escapeHTML(action.description||'')}</td>
    </tr>`).join(''):`<tr><td colspan="3">No recommended actions provided.</td></tr>`;
  const ruleHtml=ruleBlocks.length?ruleBlocks.map(([label,value])=>`
    <div class="pdf-rule">
      <h3>${escapeHTML(label)}</h3>
      <pre>${escapeHTML(formatRuleCode(value))}</pre>
    </div>`).join(''):'<p>No detection rules generated.</p>';

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>${escapeHTML(incidentReportTitle(analysis))}</title>
<style>
  @page{size:A4;margin:16mm 14mm;}
  *{box-sizing:border-box;}
  body{margin:0;background:#f3f5f7;color:#182026;font-family:Arial,Helvetica,sans-serif;font-size:11px;line-height:1.5;}
  .pdf-page{max-width:980px;margin:0 auto;background:#fff;min-height:100vh;}
  .pdf-header{background:linear-gradient(135deg,#11161b,#22282e 58%,#4b2f1a);color:#fff;padding:24px 28px;border-bottom:4px solid #d6a065;}
  .pdf-brand{font-size:11px;letter-spacing:2.5px;text-transform:uppercase;color:#f0c591;margin-bottom:10px;}
  .pdf-title{font-size:26px;font-weight:800;line-height:1.15;margin:0 0 12px;}
  .pdf-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;color:#dce4eb;font-size:10px;}
  .pdf-meta span{display:block;color:#9ba8b4;text-transform:uppercase;letter-spacing:1px;font-size:8px;margin-bottom:2px;}
  .pdf-body{padding:22px 28px 28px;}
  .pdf-section{margin:0 0 18px;page-break-inside:avoid;}
  .pdf-section.breakable{page-break-inside:auto;}
  h2{font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:0 0 9px;color:#182026;border-bottom:1px solid #d8dee4;padding-bottom:5px;}
  h3{font-size:11px;text-transform:uppercase;letter-spacing:.8px;margin:0 0 5px;color:#6f451f;}
  p{margin:0 0 8px;}
  .pdf-summary{font-size:12px;color:#27323a;background:#f7f9fb;border-left:4px solid #d6a065;padding:11px 12px;}
  .pdf-score-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;}
  .pdf-score-card{border:1px solid #d8dee4;border-radius:8px;padding:10px;background:#fbfcfd;}
  .pdf-score-card span{display:block;font-size:8px;letter-spacing:1px;text-transform:uppercase;color:#6b7780;margin-bottom:4px;}
  .pdf-score-card strong{font-size:16px;color:#182026;}
  .pdf-badge{display:inline-block;border-radius:999px;padding:3px 8px;font-weight:700;font-size:9px;letter-spacing:.7px;border:1px solid #9ba8b4;color:#27323a;background:#eef2f5;}
  .pdf-badge.critical{background:#ffe5e8;color:#9b1530;border-color:#e7a1ad;}
  .pdf-badge.high{background:#fff1df;color:#93510b;border-color:#e6bd84;}
  .pdf-badge.medium{background:#fff7d7;color:#76600a;border-color:#e1cf75;}
  .pdf-badge.low,.pdf-badge.info{background:#e8f5ed;color:#246640;border-color:#96c9a9;}
  table{width:100%;border-collapse:collapse;margin-top:8px;page-break-inside:auto;}
  tr{page-break-inside:avoid;page-break-after:auto;}
  th{background:#20272d;color:#f4e3cf;text-align:left;font-size:9px;letter-spacing:.9px;text-transform:uppercase;padding:7px;border:1px solid #3a424a;}
  td{vertical-align:top;padding:7px;border:1px solid #d8dee4;word-break:break-word;}
  tbody tr:nth-child(even){background:#f7f9fb;}
  .pdf-rule{page-break-inside:avoid;margin:0 0 12px;}
  pre{white-space:pre-wrap;word-break:break-word;background:#151a1f;color:#e6edf3;border:1px solid #2f3942;border-radius:8px;padding:10px;font-family:"Courier New",monospace;font-size:9px;line-height:1.45;margin:0;}
  .pdf-notes{min-height:80px;border:1px dashed #aeb8c2;background:#fbfcfd;border-radius:8px;padding:12px;color:#4f5b65;}
  .pdf-footer{margin-top:24px;padding-top:10px;border-top:1px solid #d8dee4;text-align:center;color:#6b7780;font-size:9px;}
  @media print{body{background:#fff;}.pdf-page{box-shadow:none;max-width:none;}.pdf-section{break-inside:avoid;}.pdf-section.breakable{break-inside:auto;}}
</style>
</head>
<body>
  <main class="pdf-page">
    <header class="pdf-header">
      <div class="pdf-brand">SOC Copilot</div>
      <h1 class="pdf-title">${escapeHTML(incidentReportTitle(analysis))}</h1>
      <div class="pdf-meta">
        <div><span>Generated Date</span>${escapeHTML(generatedAt)}</div>
        <div><span>Source File</span>${escapeHTML(incidentSourceFileName())}</div>
        <div><span>Severity</span><span class="pdf-badge ${incidentSeverityClass(level)}">${escapeHTML(level)}</span></div>
      </div>
    </header>
    <section class="pdf-body">
      <section class="pdf-section"><h2>Executive Summary</h2><div class="pdf-summary">${htmlLineBreaks(analysis.summary||'No executive summary was generated.')}</div></section>
      <section class="pdf-section"><h2>Incident Classification</h2><p>${escapeHTML(incidentClassification(analysis))}</p></section>
      <section class="pdf-section"><h2>Risk Score, Severity, Confidence</h2><div class="pdf-score-grid">
        <div class="pdf-score-card"><span>Risk Score</span><strong>${score.toFixed(1)}</strong></div>
        <div class="pdf-score-card"><span>Severity</span><strong>${escapeHTML(level)}</strong></div>
        <div class="pdf-score-card"><span>Confidence</span><strong>${(confidence*100).toFixed(0)}%</strong></div>
        <div class="pdf-score-card"><span>Timeline Events</span><strong>${lastAttackTimelineEvents.length}</strong></div>
      </div></section>
      <section class="pdf-section breakable"><h2>Attack Timeline</h2><table><thead><tr><th>#</th><th>Timestamp</th><th>Stage</th><th>Severity</th><th>Original Log Line</th></tr></thead><tbody>${timelineRows}</tbody></table></section>
      <section class="pdf-section breakable"><h2>MITRE ATT&CK Techniques</h2><table><thead><tr><th>Technique ID</th><th>Technique Name</th></tr></thead><tbody>${mitreRows}</tbody></table></section>
      <section class="pdf-section breakable"><h2>IOC Table</h2><table><thead><tr><th>Type</th><th>Category</th><th>Value</th></tr></thead><tbody>${iocRows}</tbody></table></section>
      <section class="pdf-section breakable"><h2>Detection Rules</h2>${ruleHtml}</section>
      <section class="pdf-section breakable"><h2>Recommended Response Actions</h2><table><thead><tr><th>Priority</th><th>Action</th><th>Description</th></tr></thead><tbody>${actionRows}</tbody></table></section>
      <section class="pdf-section"><h2>Analyst Notes</h2><div class="pdf-notes">Add containment decisions, validation notes, affected assets, ticket references, and follow-up owners here.</div></section>
      <footer class="pdf-footer">Generated by SOC Copilot</footer>
    </section>
  </main>
</body>
</html>`;
}

function openIncidentReportModal(){
  const modal=document.getElementById('incident-report-modal');
  const preview=document.getElementById('incident-report-preview');
  lastIncidentReportText=buildIncidentReportText();
  if(preview)preview.textContent=lastIncidentReportText;
  if(modal){modal.classList.add('show');modal.setAttribute('aria-hidden','false');}
  if(!lastFileAnalysisResult)notify('Analyze a file first to generate an incident report.','info');
}

function closeIncidentReportModal(){
  const modal=document.getElementById('incident-report-modal');
  if(modal){modal.classList.remove('show');modal.setAttribute('aria-hidden','true');}
}

async function copyIncidentReport(){
  const text=lastIncidentReportText||buildIncidentReportText();
  try{
    if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(text);
    else{
      const ta=document.createElement('textarea');
      ta.value=text;ta.style.position='fixed';ta.style.opacity='0';
      document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();
    }
    notify('Incident report copied.','ok');
  }catch(e){notify('Copy failed: '+e.message,'err');}
}

function downloadIncidentReportPdf(){
  if(!lastFileAnalysisResult){notify('Analyze a file first to generate an incident report.','info');return;}
  const reportWindow=window.open('','_blank','width=1100,height=850');
  if(!reportWindow){notify('Allow pop-ups to export the PDF report.','err');return;}
  reportWindow.document.open();
  reportWindow.document.write(buildIncidentReportHtml());
  reportWindow.document.close();
  let didPrint=false;
  const triggerPrint=()=>{
    if(didPrint)return;
    didPrint=true;
    try{reportWindow.focus();reportWindow.print();}catch(e){}
  };
  reportWindow.onload=triggerPrint;
  setTimeout(triggerPrint,650);
  notify('PDF report opened. Choose Save as PDF in the print dialog.','ok');
}

function faDragOver(e){e.preventDefault();document.getElementById('fa-zone').classList.add('dragging');}
function faDrop(e){e.preventDefault();document.getElementById('fa-zone').classList.remove('dragging');const f=e.dataTransfer.files[0];if(f)faSetFile(f);}
function faSelect(e){const f=e.target.files[0];if(f)faSetFile(f);}
function faSetFile(f){selFile=f;lastFileAnalysisResult=null;lastIncidentReportText='';const i=document.getElementById('fa-info');i.style.display='block';i.innerHTML=`<b>${f.name}</b> - ${(f.size/1024).toFixed(1)} KB`;resetAttackTimeline('Analyze the selected file to build the attack timeline.');notify('File selected: '+f.name,'info');}
function renderFileAnalysisResult(a){
  lastFileAnalysisResult=a||null;
  const sev=a.severity||{};const sc=sev.score||0;const lv=(sev.level||'info').toUpperCase();
  const rc=lv==='CRITICAL'?'var(--red)':lv==='HIGH'?'var(--orange)':lv==='MEDIUM'?'var(--yellow)':'var(--green)';
  document.getElementById('fa-score').textContent=sc.toFixed(1);document.getElementById('fa-score').style.color=rc;
  document.getElementById('fa-level').textContent=lv;document.getElementById('fa-level').style.color=rc;
  document.getElementById('fa-bar').style.width=(sc*10)+'%';
  const drivers=Array.isArray(sev.score_drivers)?sev.score_drivers.filter(Boolean).slice(0,6):[];
  document.getElementById('fa-conf').textContent=`Confidence: ${((sev.confidence||0)*100).toFixed(0)}%${drivers.length?` | Score drivers: ${drivers.join(', ')}`:''}`;
  document.getElementById('fa-summary').textContent=a.summary||'Analysis complete';document.getElementById('fa-summary').style.color='var(--text2)';
  document.getElementById('fa-mitre').innerHTML=(a.mitre_techniques||[]).map(t=>`<a class="tag tp mitre-tag-link" href="https://attack.mitre.org/techniques/${t.technique_id}/" target="_blank" rel="noreferrer">${t.technique_id} - ${t.technique_name||''}</a>`).join('')||'<span style="color:var(--text3);font-size:10px;">None</span>';
  document.getElementById('fa-iocs').innerHTML=renderIOCMarkup(a.iocs||{},{sourceKey:'file-analysis'});
  document.getElementById('fa-rules').innerHTML=renderRuleMarkup(a.detection_rules||{});
  document.getElementById('fa-actions').innerHTML=renderActionMarkup(a.recommended_actions||[]);
  addAttackMapIOCsFromAnalysis(a.iocs||{});
}
async function uploadAnalyze(){
  if(!selFile){notify('Select a file first','err');return;}
  const analysisFile=selFile;
  const pid=getProjectId();
  const type=document.getElementById('fa-type').value;
  const chunkSize=getChunkSize();
  const btn=document.getElementById('fa-btn');btn.disabled=true;btn.textContent='Processing...';
  const info=document.getElementById('fa-info');info.style.display='block';info.style.color='var(--cyan)';
  try{
    info.innerHTML=`Uploading <b>${analysisFile.name}</b> to project ${pid}...`;
    const upload=await uploadProjectFile(analysisFile,pid,type);
    lastUploadedProjectFile={projectId:String(pid),fileId:upload.file_id,fileName:upload.file_name||analysisFile.name};
    info.innerHTML=`Processing and chunking <b>${lastUploadedProjectFile.fileName}</b>...`;
    const indexing=await rebuildProjectIndex(pid,{fileId:lastUploadedProjectFile.fileId,chunkSize,contentType:type});
    info.innerHTML=`Running analysis on indexed content for <b>${lastUploadedProjectFile.fileName}</b>...`;
    const d=await apiFetch(`/api/v1/analysis/asset/${pid}`,{method:'POST',body:JSON.stringify({file_id:lastUploadedProjectFile.fileId,input_type:type})});
    const a=d.analysis?.analysis_result||d.analysis||{};
    renderFileAnalysisResult(a);
    await buildAttackTimelineFromFile(analysisFile);
    populateInvestigationFromFileAnalysis();
    lastChatContext=`file ${lastUploadedProjectFile.fileName} - project ${pid}`;
    clearChat();
    info.style.color='var(--green)';
    info.innerHTML=`<b>${lastUploadedProjectFile.fileName}</b> is now uploaded, chunked, indexed, and ready for chat.<br><span style="font-size:10px;color:var(--text2)">Chunks: ${indexing.process.inserted_chunks||0} - Indexed vectors: ${indexing.push.inserted_items_count||0}</span>`;
    notify('File uploaded, processed into chunks, indexed, and linked to chat context.','ok');
  }catch(e){info.style.color='var(--red)';info.innerHTML=`<b>File Analysis failed</b><br><span style="font-size:11px;color:#ff9caf">${escapeHTML(e.message)}</span>`;notify('Failed: '+e.message,'err');}
  finally{btn.disabled=false;btn.textContent='Analyze';}
}

// Admin
function setAdminTab(tab,btn){
  adminTab=tab;
  document.querySelectorAll('#page-admin .admin-tabs .tbtn').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('#page-admin .admin-tab-panel').forEach(p=>p.classList.remove('active'));
  if(btn)btn.classList.add('active');
  document.getElementById(`admin-panel-${tab}`)?.classList.add('active');
  if(tab==='status')loadKBStats();
}

function adminDragOver(e){e.preventDefault();document.getElementById('admin-upload-zone').classList.add('dragging');}
function adminDrop(e){e.preventDefault();document.getElementById('admin-upload-zone').classList.remove('dragging');adminSetFiles(e.dataTransfer.files);}
function adminSelectFile(e){adminSetFiles(e.target.files);}
function adminFormatSize(bytes=0){
  if(bytes>=1024*1024)return `${(bytes/(1024*1024)).toFixed(1)} MB`;
  return `${(bytes/1024).toFixed(1)} KB`;
}
function adminSetFiles(fileList){
  const files=Array.from(fileList||[]);
  if(!files.length)return;
  const seen=new Set();
  const unique=[];
  adminSkippedDuplicateCount=0;
  files.forEach(file=>{
    const key=file.name.toLowerCase();
    if(seen.has(key)){adminSkippedDuplicateCount+=1;return;}
    seen.add(key);
    unique.push(file);
  });
  adminSelFiles=unique;
  adminSelFile=unique[0]||null;
  renderAdminSelectedFiles();
}
function renderAdminSelectedFiles(statuses={}){
  const info=document.getElementById('admin-upload-file-info');
  if(!info)return;
  if(!adminSelFiles.length){
    adminSkippedDuplicateCount=0;
    info.style.display='none';
    info.innerHTML='';
    return;
  }
  info.style.display='block';
  const totalSize=adminSelFiles.reduce((sum,file)=>sum+file.size,0);
  const duplicateNames=adminSelFiles.reduce((acc,file)=>{
    const name=file.name.toLowerCase();
    acc[name]=(acc[name]||0)+1;
    return acc;
  },{});
  info.innerHTML=`<div class="admin-bulk-summary">
      <strong>${adminSelFiles.length} file${adminSelFiles.length===1?'':'s'} selected</strong>
      <span>Total size: ${adminFormatSize(totalSize)}${adminSkippedDuplicateCount?` - Skipped duplicate names: ${adminSkippedDuplicateCount}`:''}</span>
    </div>
    <div class="admin-file-queue">
      ${adminSelFiles.map((file,index)=>{
        const statusInfo=statuses[index]||'queued';
        const status=typeof statusInfo==='string'?statusInfo:(statusInfo.state||'queued');
        const error=typeof statusInfo==='string'?'':(statusInfo.error||'');
        const duplicate=duplicateNames[file.name.toLowerCase()]>1;
        return `<div class="admin-file-row">
          <span class="admin-file-status admin-file-status-${status}">${status}</span>
          <span class="admin-file-name" title="${escapeHTML(file.name)}">${escapeHTML(file.name)}${duplicate?' <em>duplicate name</em>':''}</span>
          <span class="admin-file-size">${adminFormatSize(file.size)}</span>
          ${error?`<span class="admin-file-error">${escapeHTML(error)}</span>`:''}
        </div>`;
      }).join('')}
    </div>`;
}

function adminDefaultChunkSize(){
  return 1200;
}

function setAdminChunkDefault(){
  const input=document.getElementById('admin-chunk-size');
  if(input)input.value=adminDefaultChunkSize();
}

function getAdminChunkSize(){
  const input=document.getElementById('admin-chunk-size');
  const raw=parseInt(input?.value,10);
  const size=Number.isFinite(raw)?Math.min(Math.max(raw,50),5000):1200;
  if(input)input.value=String(size);
  return size;
}

async function adminUploadFile(){
  if(!adminSelFiles.length&&adminSelFile)adminSelFiles=[adminSelFile];
  if(!adminSelFiles.length){notify('Select one or more files first','err');return;}
  const pid=getProjectId();
  const contentType=document.getElementById('admin-content-type').value;
  const sourceName=document.getElementById('admin-source-name').value.trim();
  const description=document.getElementById('admin-description').value.trim();
  const chunkSize=getAdminChunkSize();
  if(!sourceName){notify('Enter source name','err');return;}
  const btn=document.getElementById('admin-upload-btn');
  const box=document.getElementById('admin-upload-status');
  btn.disabled=true;btn.textContent='Uploading...';
  const statuses={};
  renderAdminSelectedFiles(statuses);
  box.textContent=`Uploading ${adminSelFiles.length} file${adminSelFiles.length===1?'':'s'}, chunking at ${chunkSize} characters, and indexing sequentially...`;
  let indexed=0;
  const failed=[];
  try{
    for(let i=0;i<adminSelFiles.length;i+=1){
      const file=adminSelFiles[i];
      statuses[i]='uploading';
      renderAdminSelectedFiles(statuses);
      box.textContent=`Uploading ${i+1}/${adminSelFiles.length}: ${file.name}`;
      const fd=new FormData();
      fd.append('file',file);
      fd.append('content_type',contentType);
      fd.append('source_name',sourceName);
      fd.append('description',description);
      fd.append('chunk_size',String(chunkSize));
      try{
        const res=await fetch(`${API()}/api/v1/admin/upload/${pid}`,{method:'POST',body:fd});
        const data=await res.json().catch(()=>({signal:'admin_upload_failed'}));
        if(!res.ok)throw new Error(data.detail||data.signal||'admin_upload_failed');
        statuses[i]='indexed';
        indexed+=1;
      }catch(fileErr){
        statuses[i]={state:'failed',error:fileErr.message};
        failed.push(`${file.name}: ${fileErr.message}`);
      }
      renderAdminSelectedFiles(statuses);
    }
    box.innerHTML=`<b>Indexed ${indexed}/${adminSelFiles.length} files</b><br><span style="font-size:11px;color:var(--text2)">Type: ${escapeHTML(contentType)} - Source: ${escapeHTML(sourceName)} - Chunk size: ${chunkSize}${failed.length?` - Failed: ${failed.length}`:''}</span>`;
    notify(`Indexed ${indexed}/${adminSelFiles.length} files` ,indexed?'ok':'err');
    if(indexed===adminSelFiles.length){
      adminSelFile=null;
      adminSelFiles=[];
      adminSkippedDuplicateCount=0;
      document.getElementById('admin-file-input').value='';
      document.getElementById('admin-upload-file-info').style.display='none';
    }
    loadKBStats();
  }catch(e){
    box.textContent=`Upload failed: ${e.message}`;
    notify('Admin upload failed: '+e.message,'err');
  }finally{
    btn.disabled=false;btn.textContent='Upload & Index';
  }
}

function quickFill(name){
  const q=QUICK_URLS[name];
  if(!q)return;
  document.getElementById('admin-url').value=q.url;
  document.getElementById('admin-url-type').value=q.type;
  document.getElementById('admin-url-source').value=q.name;
  document.getElementById('admin-url-description').value=q.description||'';
}

async function adminFetchURL(){
  const pid=getProjectId();
  const url=document.getElementById('admin-url').value.trim();
  const contentType=document.getElementById('admin-url-type').value;
  const sourceName=document.getElementById('admin-url-source').value.trim();
  const description=document.getElementById('admin-url-description').value.trim();
  if(!url||!sourceName){notify('Enter URL and source name','err');return;}
  const btn=document.getElementById('admin-fetch-btn');
  const box=document.getElementById('admin-fetch-status');
  btn.disabled=true;btn.textContent='Fetching...';
  box.textContent='Fetching remote content, extracting text, chunking, and indexing...';
  try{
    const d=await apiFetch(`/api/v1/admin/fetch-url/${pid}`,{method:'POST',body:JSON.stringify({url,content_type:contentType,source_name:sourceName,description})});
    box.innerHTML=`<b>${d.source_name}</b> fetched and indexed.<br><span style="font-size:11px;color:var(--text2)">Characters: ${d.characters_fetched} - Chunks: ${d.chunks_created} - Vectors: ${d.vectors_indexed}</span>`;
    notify('Remote source fetched and indexed.','ok');
    loadKBStats();
  }catch(e){
    box.textContent=`Fetch failed: ${e.message}`;
    notify('Fetch failed: '+e.message,'err');
  }finally{
    btn.disabled=false;btn.textContent='Fetch & Index';
  }
}

async function loadKBStats(){
  const pid=getProjectId();
  try{
    const d=await apiFetch(`/api/v1/admin/kb-status/${pid}`);
    document.getElementById('admin-kb-summary').innerHTML=`
      <div class="admin-summary-item"><span>Total Vectors</span><strong>${d.total_vectors||0}</strong></div>
      <div class="admin-summary-item"><span>Documents</span><strong>${d.documents||0}</strong></div>
      <div class="admin-summary-item"><span>Total Chunks</span><strong>${d.total_chunks||0}</strong></div>
    `;

    const types=d.by_content_type||{};
    const typeEntries=Object.entries(types).sort((a,b)=>b[1]-a[1]);
    document.getElementById('admin-kb-types').innerHTML=typeEntries.length
      ? typeEntries.map(([name,count])=>`<div class="admin-list-item"><span>${name}</span><strong>${count}</strong></div>`).join('')
      : '<div class="admin-empty">No indexed content yet.</div>';

    const sources=d.sources||[];
    document.getElementById('admin-kb-sources').innerHTML=sources.length
      ? sources.map(src=>`<div class="admin-source-row"><div><div class="admin-source-name">${src.source_name||src.asset_name}</div><div class="admin-source-meta">${src.content_type||'uncategorized'} - ${src.asset_name}</div></div><div class="admin-source-count">${src.chunks||0} chunks</div></div>`).join('')
      : '<div class="admin-empty">No sources available.</div>';
  }catch(e){
    document.getElementById('admin-kb-types').innerHTML='<div class="admin-empty">Failed to load KB status.</div>';
    document.getElementById('admin-kb-sources').innerHTML='<div class="admin-empty">Failed to load source list.</div>';
    notify('KB status failed: '+e.message,'err');
  }
}

async function clearKB(){
  const pid=getProjectId();
  const ok=window.confirm('Clear all indexed admin content for this project?');
  if(!ok)return;
  try{
    const d=await apiFetch(`/api/v1/admin/clear/${pid}`,{method:'POST',body:JSON.stringify({})});
    notify(`Knowledge base cleared. Deleted ${d.deleted_chunks||0} chunks.`,'ok');
    loadKBStats();
  }catch(e){
    notify('Clear failed: '+e.message,'err');
  }
}

// Investigation
function addEv(){const i=document.getElementById('new-ev');const t=i.value.trim();if(!t)return;invAutoCorrelated=false;events.push(t);i.value='';renderEvs();}
function clearEvs(){events=[];invAutoCorrelated=false;renderEvs();document.getElementById('chain-sev').textContent='-';document.getElementById('chain-content').innerHTML='<div style="padding:30px;text-align:center;color:var(--text3);font-size:11px;">Add at least 2 events and click Investigate</div>';}
function renderEvs(){
  document.getElementById('ev-cnt').textContent=events.length;
  const list=document.getElementById('ev-list');
  if(!events.length){list.innerHTML='<div style="padding:20px;text-align:center;color:var(--text3);font-size:11px;">Add events below</div>';return;}
  const label=invAutoCorrelated?'<div class="auto-corr-side-label">Auto-correlated from analyzed log</div>':'';
  list.innerHTML=label+events.map((ev,i)=>{
    const ip=(ev.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)||[])[0];
    const user=(ev.match(/(?:user[=: ]+|User=)([A-Za-z0-9._-]+)/i)||[])[1];
    const ts=(ev.match(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/)||[])[0];
    return`<div class="ev-item"><span class="ev-num">#${i+1}</span>
      ${ts?`<div class="ev-time">${ts}</div>`:''}
      <div class="ev-content">${ev.substring(0,120)}</div>
      <div class="ev-tags">${ip?`<span class="et et-ip">${ip}</span>`:''}${user?`<span class="et et-user">${user}</span>`:''}</div>
    </div>`;
  }).join('');
}

async function runInv(){
  if(events.length<2){notify('Add at least 2 events','err');return;}
  const btn=document.getElementById('inv-btn');btn.disabled=true;btn.textContent='Investigating...';
  document.getElementById('inv-loading').classList.add('show');
  try{
    const d=await apiFetch('/api/v1/investigation/analyze',{method:'POST',body:JSON.stringify({events})});
    const inv=d.investigation||{};
    const sev=inv.overall_severity||{};
    document.getElementById('chain-sev').textContent=`${(sev.level||'').toUpperCase()} - ${(sev.score||0).toFixed(1)}`;
    let html='';
    html+=renderInvestigationOverview(inv,sev);
    if(inv.attack_story)html+=`<div class="story-box"><div class="story-label">ATTACK STORY</div><div class="story-text">${escapeHTML(inv.attack_story)}</div></div>`;
    const tl=inv.timeline||[];
    const dc={ia:'var(--red)',ex:'var(--orange)',pe:'var(--purple)',la:'var(--cyan)',di:'var(--yellow)'};
    if(tl.length){
      html+='<div class="chain-steps">';
      tl.forEach(step=>{const k=tacticToneKey(step.tactic);const col=dc[k]||'var(--cyan)';
        html+=`<div class="chain-step"><div class="chain-dot d-${k}">+</div>
          <div class="chain-content">
            <div style="display:flex;align-items:center;gap:8px"><div class="chain-tname" style="color:${col}">${escapeHTML(prettyLabel(step.tactic||'Unknown'))}</div><span class="chain-tid" style="background:rgba(255,255,255,.05);color:${col}">${escapeHTML(step.technique_id||'')}</span></div>
            <div class="chain-desc">${escapeHTML(step.description||'')}</div>
            <div class="chain-ev-row">Event #${escapeHTML(step.event_number||'?')} - ${escapeHTML(step.evidence||'')}<span style="margin-left:auto;color:var(--green)">Conf:${((step.confidence||0)*100).toFixed(0)}%</span></div>
          </div></div>`;
      });
      html+='</div>';
    }
    if(inv.current_stage)html+=`<div class="stage-boxes">
      <div class="stage-box"><div class="stage-lbl">CURRENT STAGE</div><div class="stage-val">${escapeHTML(prettyLabel(inv.current_stage))}</div><div class="stage-sub">${escapeHTML(inv.current_stage_description||'')}</div></div>
      <div class="stage-box" style="border-color:rgba(255,45,85,.2)"><div class="stage-lbl">NEXT PREDICTED</div>${(inv.next_steps_prediction||[]).slice(0,3).map(s=>`<div class="next-item">${escapeHTML(s.technique_name||s.technique_id||'')}</div>${s.description?`<div class="next-desc">${escapeHTML(s.description)}</div>`:''}`).join('')}</div>
    </div>`;
    html+=`<div class="inv-section"><div class="inv-section-title">Pivot Points</div>${renderInvPivotPoints(inv.pivot_points||[])}</div>`;
    html+=`<div class="inv-section"><div class="inv-section-title">Kill Chain</div>${renderInvKillChain(inv.kill_chain||[])}</div>`;
    html+=`<div class="inv-section"><div class="inv-section-title">IOCs</div><div class="ioc-list">${renderIOCMarkup(inv.iocs||{},{sourceKey:'investigation-chain'})}</div></div>`;
    html+=`<div class="inv-section"><div class="inv-section-title">Detection Rules</div>${renderCompactRuleBlocks(inv.detection_rules||{})}</div>`;
    html+=`<div class="inv-section"><div class="inv-section-title">Recommended Actions</div><div class="action-list">${renderActionMarkup(inv.recommended_actions||[])}</div></div>`;
    document.getElementById('chain-content').innerHTML=html||'<div style="padding:30px;text-align:center;color:var(--text3);">No chain data</div>';
    if(d.investigation_uuid)notify(`Investigation saved: ${d.investigation_uuid.substring(0,8)}...`,'ok');
    else notify('Investigation complete!','ok');
  }catch(e){notify('Investigation failed: '+e.message,'err');}
  finally{btn.disabled=false;btn.textContent='Investigate';document.getElementById('inv-loading').classList.remove('show');}
}

// Chat
function clearChat(){
  chatHist=[];
  const ctx=lastChatContext?` Current context: ${lastChatContext}.`:' Upload and analyze a file to create a fresh chat context.';
  document.getElementById('chat-msgs').innerHTML=`<div class="chat-msg"><div class="chat-av av-ai">AI</div><div class="chat-bubble cb-ai">Chat ready.${ctx} Ask me about the indexed file content.</div></div>`;
}

const CHAT_SOURCE_LABELS={
  '':'All Sources',
  malware_report:'Malware Reports',
  yara_rule:'YARA Rules',
  sigma_rule:'Sigma Rules',
  ioc_list:'IOC Lists'
};

function detectChatSource(question=''){
  const text=String(question||'').toLowerCase();
  if(/\b(?:yara|apt\s+rule|strings?|condition)\b/.test(text))return 'yara_rule';
  if(/\b(?:sigma|detection\s+rule|siem)\b/.test(text))return 'sigma_rule';
  if(/\b(?:ioc|iocs|ip|domain|hash|indicator|indicators)\b/.test(text))return 'ioc_list';
  if(/\b(?:malware\s+report|behavior|behaviour|mitre|cve|exploit)\b/.test(text))return 'malware_report';
  return '';
}

async function sendChat(){
  const inp=document.getElementById('chat-in');const q=inp.value.trim();if(!q)return;
  const pid=getProjectId();
  const selectedSource=document.getElementById('chat-source-type')?.value||'auto';
  const contentType=selectedSource==='auto'?detectChatSource(q):selectedSource;
  const autoLabel=selectedSource==='auto'?`<div class="chat-source-label">Auto-selected source: ${CHAT_SOURCE_LABELS[contentType]||'All Sources'}</div>`:'';
  const sourceName=document.getElementById('chat-source-name')?.value.trim()||'';
  const msgs=document.getElementById('chat-msgs');
  msgs.innerHTML+=`<div class="chat-msg user"><div class="chat-av av-user">You</div><div class="chat-bubble cb-user">${q}</div></div>`;
  msgs.innerHTML+=`<div class="chat-msg" id="typ"><div class="chat-av av-ai">AI</div><div class="chat-bubble cb-ai" style="color:var(--text3)">${autoLabel}Thinking...</div></div>`;
  msgs.scrollTop=msgs.scrollHeight;inp.value='';document.getElementById('chat-btn').disabled=true;
  chatHist.push({role:'user',content:q});
  try{
    const payload={question:q,chat_history:chatHist.slice(-6),limit:5};
    if(contentType&&selectedSource!=='auto'){
      payload.content_type=contentType;
    }
    if(sourceName)payload.source_name=sourceName;
    const d=await apiFetch(`/api/v1/chat/${pid}`,{method:'POST',body:JSON.stringify(payload)});
    document.getElementById('typ')?.remove();
    const ans=d.answer||'No answer';
    msgs.innerHTML+=`<div class="chat-msg"><div class="chat-av av-ai">AI</div><div class="chat-bubble cb-ai">${autoLabel}${ans}</div></div>`;
    chatHist.push({role:'assistant',content:ans});msgs.scrollTop=msgs.scrollHeight;
  }catch(e){document.getElementById('typ')?.remove();msgs.innerHTML+=`<div class="chat-msg"><div class="chat-av av-ai">AI</div><div class="chat-bubble cb-ai" style="color:var(--red)">Error: ${e.message}</div></div>`;}
  finally{document.getElementById('chat-btn').disabled=false;}
}

// Reference
async function loadRef(){
  try{const d=await apiFetch('/api/v1/reference/event-ids');refData=d.event_ids||{};renderRefList('all','');}
  catch(e){notify('Failed to load Event IDs: '+e.message,'err');}
}
function setRefP(p,btn){document.querySelectorAll('#page-reference .tbtn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');refPlatform=p;renderRefList(p,document.getElementById('ref-srch').value);}
function filterRef(q){renderRefList(refPlatform,q);}
function renderRefList(platform,search){
  const list=document.getElementById('ref-list');
  let items=[];
  const ps=platform==='all'?['windows','sysmon']:[platform];
  ps.forEach(p=>Object.entries(refData[p]||{}).forEach(([id,det])=>{
    if(!search||id.includes(search)||(det.name||'').toLowerCase().includes(search.toLowerCase()))
      items.push({id,platform:p,...det});
  }));
  list.innerHTML=items.map(it=>{const rc=it.relevance==='critical'?'rrel-c':it.relevance==='high'?'rrel-h':'rrel-m';return`<div class="ref-item" onclick="showRefDet('${it.platform}','${it.id}')"><span class="ref-id">${it.id}</span><span class="ref-name">${(it.name||'').substring(0,28)}</span><span class="rrel ${rc}">${it.relevance||''}</span></div>`;}).join('')||'<div style="padding:20px;text-align:center;color:var(--text3);font-size:10px;">No results</div>';
}
function showRefDet(platform,id){
  document.querySelectorAll('.ref-item').forEach(i=>i.classList.remove('active'));
  const det=(refData[platform]||{})[id];if(!det)return;
  const ml=(det.mitre||[]).map(t=>`<span class="tag tp">${t}</span>`).join(' ');
  document.getElementById('ref-detail').innerHTML=`
    <div class="ref-detail-id">${id}</div><div class="ref-detail-name">${det.name||''}</div>
    <div style="margin-top:8px;display:flex;gap:6px;align-items:center;">
      <span class="tag ${det.relevance==='critical'?'tr':det.relevance==='high'?'tp':'tc'}">${det.relevance||''}</span>
      <span class="tag tc">${platform.toUpperCase()}</span>${ml}
    </div>
    <div style="margin-top:16px"><div style="font-size:8px;letter-spacing:2px;color:var(--text3);margin-bottom:6px;">DESCRIPTION</div><div style="font-size:12px;line-height:1.6;color:var(--text2);">${det.description||''}</div></div>
    <div style="margin-top:14px"><div style="font-size:8px;letter-spacing:2px;color:var(--text3);margin-bottom:6px;">INVESTIGATION TIPS</div><div class="ref-tips">${det.investigation_tips||'No tips available'}</div></div>`;
}

// History
async function loadHist(){
  const filt=document.getElementById('hist-filt').value;
  const url='/api/v1/analysis/history?page_size=50'+(filt?`&risk_level=${filt}`:'');
  try{
    const d=await apiFetch(url);const items=d.items||[];
    const rows=document.getElementById('hist-rows');
    if(!items.length){rows.innerHTML='<div style="padding:20px;text-align:center;color:var(--text3);font-size:11px;">No analyses found</div>';return;}
    rows.innerHTML=items.map(r=>{
      const rl=r.risk_level||'info';
      const rc=rl==='critical'?'var(--red)':rl==='high'?'var(--orange)':rl==='medium'?'var(--yellow)':'var(--green)';
      return`<div class="hist-row" onclick="viewUUID('${r.analysis_uuid}')">
        <span class="hist-uuid">${(r.analysis_uuid||'').substring(0,8)}...</span>
        <span style="font-size:11px;">${r.title||'N/A'}</span>
        <span style="font-family:var(--mono);font-size:9px;color:var(--text2);">${r.input_type||''}</span>
        <span style="color:${rc};font-size:10px;font-weight:700;">${rl.toUpperCase()}</span>
        <span style="font-family:var(--mono);font-size:10px;color:${rc};">${(r.risk_score||0).toFixed(1)}</span>
        <span style="font-family:var(--mono);font-size:9px;color:var(--text3);">${r.created_at?new Date(r.created_at).toLocaleDateString():''}</span>
      </div>`;
    }).join('');
  }catch(e){notify('History error: '+e.message,'err');}
}

async function viewUUID(uuid){
  try{
    const d=await apiFetch(`/api/v1/analysis/history/${uuid}`);
    const a=d.analysis?.analysis_result||d.analysis||{};
    showPage('analyzer',null);
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.querySelectorAll('.nav-item')[1].classList.add('active');
    curUUID=uuid;
    renderResult(a,uuid);
    document.getElementById('feedback-row').style.display='block';
    document.getElementById('alert-input').value=d.analysis?.input_text||'';
    notify('Analysis loaded','info');
  }catch(e){notify('Load error: '+e.message,'err');}
}

// IOC Enrichment
let iocList = [];
const IOC_API_KEY_STORAGE=[
  {id:'vt-key',key:'soc_copilot_vt_api_key'},
  {id:'abuse-key',key:'soc_copilot_abuseipdb_api_key'},
  {id:'shodan-key',key:'soc_copilot_shodan_api_key'}
];

function restoreIOCAPIKeys(){
  IOC_API_KEY_STORAGE.forEach(({id,key})=>{
    const el=document.getElementById(id);
    if(!el)return;
    const saved=localStorage.getItem(key);
    if(saved!==null&&el.value!==saved)el.value=saved;
  });
}

function saveIOCAPIKey(id){
  const item=IOC_API_KEY_STORAGE.find(entry=>entry.id===id);
  const el=document.getElementById(id);
  if(!item||!el)return;
  localStorage.setItem(item.key,el.value);
}

function initIOCAPIKeyPersistence(){
  restoreIOCAPIKeys();
  IOC_API_KEY_STORAGE.forEach(({id})=>{
    const el=document.getElementById(id);
    if(!el||el.dataset.persistReady==='1')return;
    el.dataset.persistReady='1';
    el.addEventListener('input',()=>saveIOCAPIKey(id));
    el.addEventListener('change',()=>saveIOCAPIKey(id));
  });
}

function iocNow(){return new Date().toISOString();}
function ensureIOCRecord(ioc={}){return {...ioc,addedAt:ioc.addedAt||ioc.added_at||ioc.created_at||iocNow()};}
function formatIOCTime(value){
  const date=value?new Date(value):new Date();
  if(Number.isNaN(date.getTime()))return 'Added recently';
  return `Added ${date.toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'})}`;
}
function toggleApiKeyVisibility(id,btn){
  const input=document.getElementById(id);
  if(!input)return;
  input.type=input.type==='password'?'text':'password';
  if(btn)btn.textContent=input.type==='password'?'SHOW':'HIDE';
}

function addIOC() {
  const inp = document.getElementById('ioc-input');
  const entries = inp.value.split(/[\n,;]+/).map(normalizeIOCInput).filter(Boolean);
  if (!entries.length) return;
  let added = 0;
  entries.forEach(v=>{
    const t = autoType(v);
    if(t==='unknown')return;
    if (iocList.find(x => x.value.toLowerCase() === v.toLowerCase() && x.type === t)) return;
    iocList.push({value: v, type: t, addedAt: iocNow()});
    added += 1;
  });
  if (!added) { notify('No valid new IOC found','info'); return; }
  inp.value = '';
  renderIOCs();
}

function autoType(v) {
  v = normalizeIOCInput(v);
  if (isValidIP(v)) return 'ip';
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(v)) return 'hash';
  if (isValidURL(v)) return 'url';
  if (isValidDomain(v)) return 'domain';
  return 'unknown';
}

function clearIOCs() { iocList = []; renderIOCs(); document.getElementById('ioc-results').innerHTML = '<div class="ioc-empty-state">Add IOCs and press Enrich All</div>'; }

function loadSampleIOCs() {
  iocList = [
    {value:'185.220.101.45', type:'ip'},
    {value:'malicious-c2.net', type:'domain'},
    {value:'d41d8cd98f00b204e9800998ecf8427e', type:'hash'},
  ].map(ensureIOCRecord);
  renderIOCs();
}

function renderIOCs() {
  document.getElementById('ioc-cnt').textContent = iocList.length;
  const ready=document.getElementById('ioc-ready-count');
  if(ready)ready.textContent=`${iocList.length} IOC(s) ready for enrichment`;
  const el = document.getElementById('ioc-entries');
  if (!iocList.length) { el.innerHTML = '<div class="ioc-list-empty">Add IOCs above</div>'; return; }
  iocList=iocList.map(ensureIOCRecord);
  el.innerHTML = iocList.map((ioc,i) => `
    <div class="ioc-entry">
      <span class="ioc-etype ioc-etype-${escapeHTML(ioc.type)}">${escapeHTML(ioc.type.toUpperCase())}</span>
      <span class="ioc-eval"><strong>${escapeHTML(ioc.value)}</strong><small>${escapeHTML(formatIOCTime(ioc.addedAt))}</small></span>
      <button class="ioc-erm" onclick="iocList.splice(${i},1);renderIOCs()" title="Remove IOC">x</button>
    </div>`).join('');
}

function yaraDragOver(e){e.preventDefault();document.getElementById('yara-zone').classList.add('dragging');}
function yaraDrop(e){e.preventDefault();document.getElementById('yara-zone').classList.remove('dragging');const f=e.dataTransfer.files[0];if(f)yaraSetFile(f);}
function yaraSelectFile(e){const f=e.target.files[0];if(f)yaraSetFile(f);}

function yaraSetFile(file){
  yaraScanFile=file;
  const info=document.getElementById('yara-file-info');
  if(info){
    info.style.display='block';
    const safeLabel=file.__safeYaraSample?`<div class="yara-safe-label">${escapeHTML(file.__safeYaraLabel||'Safe synthetic sample for YARA validation')}</div>`:'';
    info.innerHTML=`<b>${escapeHTML(file.name)}</b> - ${adminFormatSize(file.size)}${safeLabel}`;
  }
  renderGeneratedYaraRule();
}

function base64ToBytes(value){
  const binary=atob(value||'');
  const bytes=new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
  return bytes;
}

async function generateSafeYaraSample(){
  const results=document.getElementById('yara-results');
  if(results)results.innerHTML='<div class="yara-empty">Generating safe validation sample from compiled YARA rules...</div>';
  try{
    const res=await fetch(`${API()}/api/v1/yara/sample/${getProjectId()}`);
    const data=await res.json().catch(()=>({signal:'safe_yara_sample_failed'}));
    if(!res.ok)throw new Error(data.detail||data.signal||'safe_yara_sample_failed');
    if(!data.sample_base64){
      const diag=data.diagnostics||{};
      if(results){
        results.innerHTML=`<div class="yara-empty">
          <strong>${escapeHTML(data.message||'No safely matchable YARA rule found.')}</strong>
          <div class="yara-empty-small">Loaded sources: ${diag.loaded_yara_sources??0} | Usable sources: ${diag.usable_sources??0}.</div>
        </div>`;
      }
      notify(data.message||'No safely matchable YARA rule found.','info');
      return;
    }
    const bytes=base64ToBytes(data.sample_base64||'');
    const file=new File([bytes],data.file_name||'safe-yara-validation-sample.txt',{type:data.mime_type||'text/plain'});
    const selectedRules=data.selected_rules||[];
    const diag=data.diagnostics||{};
    const validatedRule=selectedRules.find(rule=>rule.validated)||selectedRules[0]||{};
    const ruleList=selectedRules.slice(0,8).map(rule=>`
      <div class="yara-sample-rule">
        <span>${escapeHTML(rule.rule_name||'YARA rule')}</span>
        <code>${escapeHTML(rule.source_name||rule.source_file||'uploaded rule')}</code>
      </div>`).join('');
    const status=selectedRules.length
      ? `Sample validated against rule: ${validatedRule.rule_name||'YARA rule'}`
      : 'Safe validation sample generated, but no harmless rule strings were available from compiled rules.';
    file.__safeYaraSample=true;
    file.__safeYaraLabel=data.label||'Matched safe validation sample';
    file.__safeYaraRules=selectedRules;
    yaraSetFile(file);
    if(results){
      results.innerHTML=`<div class="yara-empty">
        <strong>${escapeHTML(status)}</strong>
        <div class="yara-empty-small">Loaded sources: ${diag.loaded_yara_sources??0} | Usable sources: ${diag.usable_sources??0}. Run YARA Scan to validate uploaded rules.</div>
      </div>${ruleList?`<div class="yara-sample-rules"><div class="yara-generated-title">Sample should match</div>${ruleList}</div>`:''}`;
    }
    notify(selectedRules.length?'Matched safe validation sample generated.':'Safe validation sample generated.','ok');
  }catch(e){
    if(results)results.innerHTML=`<div class="yara-empty" style="color:var(--red)">Could not generate safe validation sample: ${escapeHTML(e.message)}</div>`;
    notify('Safe sample generation failed: '+e.message,'err');
  }
}

function renderGeneratedYaraRule(){
  const box=document.getElementById('yara-generated-rule');
  if(!box)return;
  const generated=lastFileAnalysisResult?.detection_rules?.yara_rule;
  if(!generated){
    box.style.display='none';
    box.innerHTML='';
    return;
  }
  box.style.display='block';
  box.innerHTML=`<div class="yara-generated-title">Generated YARA Rule</div><pre>${escapeHTML(String(generated).slice(0,1800))}</pre>`;
}

function yaraSeverityClass(level=''){
  const l=String(level||'unknown').toLowerCase();
  return ['critical','high','medium','low'].includes(l)?l:'unknown';
}

function yaraConfidencePct(value){
  const n=Number(value||0);
  if(!Number.isFinite(n))return 0;
  return Math.max(0,Math.min(100,Math.round(n>1?n:n*100)));
}

function yaraMatchMetaValue(match,keys){
  const meta=match.metadata||{};
  for(const key of keys){
    const direct=match[key];
    if(direct!==undefined&&direct!==null&&String(direct).trim()!=='')return direct;
    const mval=meta[key];
    if(mval!==undefined&&mval!==null&&String(mval).trim()!=='')return mval;
  }
  return '';
}

function yaraField(label,value,extraClass=''){
  const text=value===undefined||value===null||String(value).trim()===''?'-':value;
  return `<div class="yara-field ${extraClass}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(text)}</strong></div>`;
}

function yaraLinkField(label,value){
  const text=String(value||'').trim();
  if(!text)return yaraField(label,'-');
  const isUrl=/^https?:\/\//i.test(text);
  return `<div class="yara-field yara-field-wide"><span>${escapeHTML(label)}</span>${isUrl?`<a href="${escapeHTML(text)}" target="_blank" rel="noopener noreferrer">${escapeHTML(shortIOCValue(text,92))}</a>`:`<strong>${escapeHTML(text)}</strong>`}</div>`;
}

function renderYaraResults(data){
  document.getElementById('yara-match-count').textContent=data.matched_rules||0;
  const el=document.getElementById('yara-results');
  const matches=data.matches||[];
  const errors=data.errors||[];
  const diag=data.diagnostics||{};
  const summary=`<div class="yara-summary">
    <div class="yara-stat"><span>Scanned Rules</span><strong>${data.scanned_rules||0}</strong></div>
    <div class="yara-stat yara-stat-match"><span>Matched Rules</span><strong>${data.matched_rules||0}</strong></div>
    <div class="yara-stat"><span>Compiled Rules</span><strong>${diag.compiled_rules??0}</strong></div>
    <div class="yara-stat"><span>Skipped / Corrupted</span><strong>${(diag.failed_rules??0)+(diag.skipped_corrupted_rules??0)}</strong></div>
    <div class="yara-stat"><span>Duration</span><strong>${escapeHTML(String(data.duration_ms||0))}ms</strong></div>
  </div>`;
  const diagnostics=`<details class="yara-tech-diagnostics">
    <summary>Technical Diagnostics</summary>
    <div class="yara-diagnostics">
      <div><span>Loaded YARA sources</span><strong>${diag.loaded_yara_sources??0}</strong></div>
      <div><span>Compiled rules</span><strong>${diag.compiled_rules??0}</strong></div>
      <div><span>Skipped / incompatible</span><strong>${diag.failed_rules??0}</strong></div>
      <div><span>Corrupted rules skipped</span><strong>${diag.skipped_corrupted_rules??0}</strong></div>
      <div><span>Fallback rules</span><strong>${diag.fallback_rules??0}</strong></div>
    </div>
    ${errors.length?renderYaraErrors(errors):''}
    ${renderYaraSourceDebug(diag.sources||[])}
  </details>`;
  if(data.message){
    el.innerHTML=summary+`<div class="yara-empty">${escapeHTML(data.message)}</div>`+diagnostics;
    return;
  }
  if(!matches.length){
    el.innerHTML=summary+`<div class="yara-empty yara-no-match"><strong>No YARA matches found.</strong><div class="yara-empty-small">Static scan completed without matching uploaded YARA detection rules.</div></div>`+diagnostics;
    return;
  }
  const topConfidence=Math.max(...matches.map(match=>yaraConfidencePct(match.confidence)));
  const verdict=`<div class="yara-verdict-card">
    <div>
      <div class="yara-verdict-kicker">Static Detection Verdict</div>
      <div class="yara-verdict-title">YARA Match Detected</div>
      <div class="yara-verdict-copy">This uploaded file matched an uploaded YARA detection rule using static analysis. The file was not executed.</div>
    </div>
    <div class="yara-verdict-score"><span>Confidence</span><strong>${topConfidence}%</strong></div>
  </div>`;
  const cards=matches.map(match=>{
    const strings=(match.matched_strings||[]).slice(0,30).map(s=>`
      <tr><td>${escapeHTML(s.identifier||'$')}</td><td><code>${escapeHTML(s.value||'matched')}</code></td></tr>`).join('');
    const tags=(match.tags||[]).slice(0,8).map(tag=>`<span class="yara-tag">${escapeHTML(tag)}</span>`).join('');
    const description=yaraMatchMetaValue(match,['description','desc']);
    const author=yaraMatchMetaValue(match,['author']);
    const reference=yaraMatchMetaValue(match,['reference','references','url']);
    const date=yaraMatchMetaValue(match,['date','created','modified']);
    const engine=match.scan_engine||data.scan_engine||'yara-python';
    const source=match.source_rule_file||match.source_name||'-';
    return `<div class="yara-match-card yara-${yaraSeverityClass(match.severity)}">
      <div class="yara-match-head">
        <div>
          <div class="yara-match-label"><span class="yara-badge yara-badge-match">MATCHED</span><span class="yara-badge">${escapeHTML(String(data.scan_mode||'-').toUpperCase())}</span><span class="yara-badge">${escapeHTML(engine)}</span>${tags}</div>
          <div class="yara-rule-name">${escapeHTML(match.rule_name||'Unnamed rule')}</div>
        </div>
        <span class="yara-confidence">${yaraConfidencePct(match.confidence)}%</span>
      </div>
      <div class="yara-match-grid">
        ${yaraField('Rule name',match.rule_name||'Unnamed rule')}
        ${yaraField('Source file',source)}
        ${yaraField('Severity',String(match.severity||'unknown').toUpperCase(),`yara-sev-${yaraSeverityClass(match.severity)}`)}
        ${yaraField('Engine',engine)}
        ${yaraField('Scan mode',String(data.scan_mode||'-').toUpperCase())}
        ${yaraField('Duration',`${data.duration_ms||0}ms`)}
        ${yaraField('Scanned rules',data.scanned_rules||0)}
        ${yaraField('Date',date||'-')}
        ${yaraField('Description',description||'-','yara-field-wide')}
        ${yaraField('Author',author||'-')}
        ${yaraLinkField('Reference link',reference)}
      </div>
      <div class="yara-strings-block">
        <div class="yara-strings-title">Matched strings</div>
        ${strings?`<table class="yara-string-table"><thead><tr><th>Identifier</th><th>Matched value</th></tr></thead><tbody>${strings}</tbody></table>`:'<div class="yara-empty-small">Rule matched without exposed string details.</div>'}
      </div>
    </div>`;
  }).join('');
  el.innerHTML=verdict+summary+cards+diagnostics;
}

function renderYaraErrors(errors=[]){
  if(!errors.length)return '';
  return `<div class="yara-errors"><div class="yara-generated-title">Skipped / Incompatible Rules</div>${errors.slice(0,12).map(err=>`<div>${escapeHTML(err.rule_name||err.source_name||err.source_file||'scanner')}: ${escapeHTML(err.error||'unknown error')}</div>`).join('')}</div>`;
}

function renderYaraSourceDebug(sources=[]){
  if(!sources.length)return '';
  return `<div class="yara-source-debug">
    <div class="yara-generated-title">Reconstructed YARA Sources</div>
    ${sources.slice(0,8).map(src=>{
      const skipped=src.skipped_rules||[];
      return `
      <details>
        <summary>${escapeHTML(src.source_name||'YARA Rules')} - ${escapeHTML(src.source_file||'rules.yar')} (${src.rule_count||0} valid compiled rules${skipped.length?`, ${skipped.length} skipped`:''})${src.source_origin?` - ${escapeHTML(src.source_origin)}`:''}${src.compile_error?` - compile error`:''}</summary>
        ${src.compile_error?`<div class="yara-compile-error">${escapeHTML(src.compile_error)}</div>`:''}
        ${skipped.length?`<div class="yara-compile-error">${skipped.slice(0,12).map(item=>`${escapeHTML(item.rule_name||'unknown')}: ${escapeHTML(item.error||'corrupted rule')}`).join('<br>')}</div>`:''}
        <pre>${escapeHTML(String(src.reconstructed_source||'').slice(0,5000))}</pre>
      </details>`;
    }).join('')}
  </div>`;
}

async function runYaraScan(){
  if(!yaraScanFile){notify('Select a suspicious file first','err');return;}
  const btn=document.getElementById('yara-scan-btn');
  const loading=document.getElementById('yara-loading');
  const mode=document.getElementById('yara-scan-mode')?.value||'fast';
  const fd=new FormData();
  fd.append('file',yaraScanFile);
  fd.append('scan_mode',mode);
  btn.disabled=true;
  btn.textContent='Scanning...';
  loading?.classList.add('show');
  try{
    const res=await fetch(`${API()}/api/v1/yara/scan/${getProjectId()}`,{method:'POST',body:fd});
    const data=await res.json().catch(()=>({signal:'yara_scan_failed'}));
    if(!res.ok)throw new Error(data.detail||data.signal||'yara_scan_failed');
    renderYaraResults(data);
    notify(`YARA scan complete: ${data.matched_rules||0} match(es)`,'ok');
  }catch(e){
    document.getElementById('yara-results').innerHTML=`<div class="yara-empty" style="color:var(--red)">YARA scan failed: ${escapeHTML(e.message)}</div>`;
    notify('YARA scan failed: '+e.message,'err');
  }finally{
    btn.disabled=false;
    btn.textContent='Run YARA Scan';
    loading?.classList.remove('show');
  }
}

function scanFileAnalysisWithYara(){
  if(!selFile){notify('Select a File Analysis upload first','err');return;}
  yaraSetFile(selFile);
  const nav=document.querySelector(".nav-item[onclick=\"showPage('yarascanner',this)\"]");
  showPage('yarascanner',nav);
  notify('Loaded File Analysis upload into YARA Scanner.','ok');
}

async function runEnrichment() {
  if (!iocList.length) { notify('Add IOCs first','err'); return; }
  const btn = document.getElementById('enrich-btn');
  btn.disabled = true; btn.textContent = 'Enriching...';
  document.getElementById('ioc-loading').classList.add('show');
  const vtKey = document.getElementById('vt-key').value.trim();
  const abKey = document.getElementById('abuse-key').value.trim();
  try {
    const d = await apiFetch('/api/v1/ioc/enrich', {method:'POST', body: JSON.stringify({
      iocs: iocList.map(item=>({value:item.value,type:item.type})),
      virustotal_key: vtKey || null,
      abuseipdb_key: abKey || null
    })});
    const results=d.results||[];
    renderIOCResults(results);
    addAttackMapIOCsFromEnrichment(results);
    notify(`Enriched ${results.length} IOC(s)`,'ok');
  } catch(e) {
    document.getElementById('ioc-results').innerHTML=`<div class="ioc-empty-state ioc-error-state"><strong>Enrichment failed</strong><span>${escapeHTML(e.message)}</span></div>`;
    notify('Enrichment failed: '+e.message,'err');
  }
  finally { btn.disabled=false; btn.textContent='Enrich All'; document.getElementById('ioc-loading').classList.remove('show'); }
}

function verdictClass(v) { return v==='malicious'?'vb-mal':v==='suspicious'?'vb-sus':v==='clean'?'vb-cln':'vb-unk'; }
function scoreColor(v)   { return v==='malicious'?'bad':v==='suspicious'?'sus':'ok'; }

function coverageClass(status=''){
  return status==='checked'?'ok':status==='error'?'bad':status==='missing'?'sus':'muted';
}

function renderIOCEnrichmentOverview(results=[]){
  const verdicts={malicious:0,suspicious:0,clean:0,unknown:0};
  results.forEach(r=>{
    const verdict=['malicious','suspicious','clean'].includes(r.verdict)?r.verdict:'unknown';
    verdicts[verdict]+=1;
  });
  return `<div class="ioc-overview">
    <div class="ioc-overview-card total"><span>Total IOCs</span><strong>${results.length}</strong><small>Submitted for enrichment</small></div>
    <div class="ioc-overview-card bad"><span>Malicious</span><strong>${verdicts.malicious}</strong><small>Confirmed or strongly flagged</small></div>
    <div class="ioc-overview-card warn"><span>Suspicious</span><strong>${verdicts.suspicious}</strong><small>Needs analyst validation</small></div>
    <div class="ioc-overview-card info"><span>Clean / Info</span><strong>${verdicts.clean+verdicts.unknown}</strong><small>Clean, unknown, or informational</small></div>
  </div>`;
}

function renderIOCPriority(priority={}){
  if(!priority||!priority.level)return '';
  return `<div class="ioc-priority-band ioc-priority-${escapeHTML(priority.level.toLowerCase())}">
    <div class="ioc-priority-level">${escapeHTML(priority.level)}</div>
    <div><div class="ioc-priority-label">${escapeHTML(priority.label||'Review')}</div>
    <div class="ioc-priority-reason">${escapeHTML(priority.reason||'')}</div></div>
  </div>`;
}

function renderIOCKeyFacts(facts=[]){
  if(!Array.isArray(facts)||!facts.length)return '';
  return `<div class="ioc-facts">${facts.slice(0,8).map(f=>`
    <div class="ioc-fact">
      <span>${escapeHTML(f.label||'Fact')}</span>
      <strong>${escapeHTML(f.value??'-')}</strong>
    </div>`).join('')}</div>`;
}

function renderIOCRiskReasons(reasons=[]){
  if(!Array.isArray(reasons)||!reasons.length)return '';
  return `<div class="ioc-risk-reasons">
    <div class="ioc-mini-title">Risk Reasons</div>
    <div class="ioc-reason-list">${reasons.slice(0,6).map(reason=>`<span>${escapeHTML(reason)}</span>`).join('')}</div>
  </div>`;
}

function renderIOCActions(actions=[]){
  if(!Array.isArray(actions)||!actions.length)return '';
  return `<div class="ioc-action-strip">
    <div class="ioc-mini-title">Recommended Actions</div>
    ${actions.slice(0,4).map(action=>`<div class="ioc-action-line"><span class="ap ap${action.priority||3}">[P${action.priority||3}]</span><span>${escapeHTML(action.action||'Review IOC')}${action.description?`: ${escapeHTML(action.description)}`:''}</span></div>`).join('')}
  </div>`;
}

function renderIOCSourceCoverage(coverage=[]){
  if(!Array.isArray(coverage)||!coverage.length)return '';
  return `<div class="ioc-coverage">
    ${coverage.map(src=>`<span class="ioc-coverage-pill ${coverageClass(src.status)}">${escapeHTML(src.name||'Source')}: ${escapeHTML(src.status||'unknown')}</span>`).join('')}
  </div>`;
}

function iocRiskScore(result={}){
  if(result.priority?.score!==undefined)return Number(result.priority.score);
  const confidence=Math.round(Number(result.confidence||0)*100);
  if(result.verdict==='malicious')return Math.max(confidence,85);
  if(result.verdict==='suspicious')return Math.max(confidence,50);
  if(result.verdict==='clean')return Math.min(confidence,25);
  return confidence||0;
}

function sourceVerdictClass(value=''){
  const v=String(value||'unknown').toLowerCase();
  if(v==='malicious'||v==='high'||v==='critical')return 'mal';
  if(v==='suspicious'||v==='medium'||v==='low risk')return 'sus';
  if(v==='clean'||v==='benign')return 'clean';
  return 'unk';
}

function sourceMetric(label,value){
  if(value===undefined||value===null||value===''||(Array.isArray(value)&&!value.length))return '';
  const rendered=Array.isArray(value)?value.join(', '):String(value);
  return `<span><b>${escapeHTML(label)}</b>${escapeHTML(rendered)}</span>`;
}

function formatIOCDate(value){
  if(value===undefined||value===null||value==='')return '';
  const numeric=Number(value);
  const date=!Number.isNaN(numeric)&&String(value).length<=10?new Date(numeric*1000):new Date(value);
  if(Number.isNaN(date.getTime()))return String(value);
  return date.toLocaleString([], {year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'});
}

function iocSourceBadge(kind){
  const key=String(kind||'').toLowerCase();
  const iconMap={
    virustotal:'./assets/ioc/virustotal.png',
    abuseipdb:'./assets/ioc/abuseipdb.png',
    shodan:'./assets/ioc/shodan.png'
  };
  const label=key==='virustotal'?'VirusTotal':key==='abuseipdb'?'AbuseIPDB':key==='shodan'?'Shodan':'Intel';
  return `<span class="ioc-service-badge ioc-service-${escapeHTML(key||'intel')}" aria-hidden="true"><img src="${iconMap[key]||''}" alt="${escapeHTML(label)}"></span>`;
}

function renderIOCSourceLegend(){
  return `<div class="ioc-source-legend" aria-label="Enrichment sources">
    <div>${iocSourceBadge('virustotal')}<span>VirusTotal</span></div>
    <div>${iocSourceBadge('abuseipdb')}<span>AbuseIPDB</span></div>
    <div>${iocSourceBadge('shodan')}<span>Shodan</span></div>
  </div>`;
}

function compactTags(items=[],limit=4){
  const values=(items||[]).filter(Boolean);
  const visible=values.slice(0,limit).map(tag=>`<em>${escapeHTML(tag)}</em>`).join('');
  const more=values.length>limit?`<em class="ioc-tag-more">+${values.length-limit} more</em>`:'';
  return visible+more;
}

function iocSourceRow({name,icon,verdict,summary,confidence,asn,isp,country,ports,lastSeen,labels,link,unavailable,error,extraDetails='' }){
  const status=unavailable?'Unavailable':(error||verdict||'Observed');
  const cls=sourceVerdictClass(status);
  const portTags=compactTags(ports||[],4);
  const labelTags=compactTags(labels||[],4);
  const sourceKey=String(name||'').toLowerCase().replace(/\s+/g,'');
  return `<div class="ioc-source-row ioc-source-${cls}">
    <div class="ioc-source-name">${iocSourceBadge(sourceKey)}<strong>${escapeHTML(name)}</strong></div>
    <div class="ioc-source-summary">
      <span class="ioc-source-verdict">${escapeHTML(status)}</span>
      ${sourceMetric('Confidence / Ratio',confidence)}
      ${summary?`<small>${escapeHTML(summary)}</small>`:''}
    </div>
    <div class="ioc-source-detail">
      ${sourceMetric('ASN / ISP', [asn,isp].filter(Boolean).join(' / '))}
      ${sourceMetric('Country',country)}
      ${sourceMetric('Last seen',lastSeen)}
      ${portTags?`<span><b>Open ports</b><span class="ioc-source-tags">${portTags}</span></span>`:''}
      ${labelTags?`<span><b>Threat labels</b><span class="ioc-source-tags">${labelTags}</span></span>`:''}
      ${link?`<a href="${escapeHTML(link)}" target="_blank" rel="noreferrer">Open source report</a>`:''}
      ${extraDetails}
    </div>
  </div>`;
}

function renderVTExtraDetails(vt={}){
  const rows=[
    ['Malicious',vt.malicious],
    ['Suspicious',vt.suspicious],
    ['Harmless / Clean',vt.harmless],
    ['Undetected',vt.undetected],
    ['Detection Ratio',vt.total!==undefined?`${vt.malicious||0}/${vt.total||0}`:''],
    ['Reputation',vt.reputation],
    ['Last Analysis',formatIOCDate(vt.last_analysis_date||vt.last_seen)],
    ['Threat Category',vt.popular_threat_category||vt.threat_category||vt.category],
    ['Threat Label',vt.popular_threat_label||vt.threat_label||vt.label||vt.name],
  ].filter(([,value])=>value!==undefined&&value!==null&&value!=='');
  if(!rows.length)return '';
  return `<details class="ioc-vt-extra">
    <summary>VirusTotal details</summary>
    <div>${rows.map(([label,value])=>sourceMetric(label,value)).join('')}</div>
  </details>`;
}

function resultAddedAt(result={}){
  const found=iocList.find(item=>item.value?.toLowerCase()===String(result.value||'').toLowerCase()&&item.type===result.type);
  return found?.addedAt||result.addedAt||result.created_at||iocNow();
}

function renderIOCResults(results) {
  const el = document.getElementById('ioc-results');
  if (!results.length) { el.innerHTML = '<div class="ioc-empty-state">No results</div>'; return; }
  el.innerHTML = renderIOCEnrichmentOverview(results) + results.map(r => {
    const vt = r.virustotal || {}; const ab = r.abuseipdb || {}; const sh = r.shodan || {};
    const local = r.local_context || {}; const ipwhois = r.ipwhois || {}; const rdap = r.rdap || {};
    const vc = verdictClass(r.verdict);
    const vtUnavailable = vt.available === false;
    const abUnavailable = ab.available === false;
    const shUnavailable = sh.available === false;
    const vtRatio = vtUnavailable ? '-' : vt.error ? '?' : `${vt.malicious||0}/${vt.total||0}`;
    const vtSummary = vt.error||vt.reason||`${vt.malicious||0} malicious, ${vt.suspicious||0} suspicious, ${vt.harmless||0} harmless, ${vt.undetected||0} undetected`;
    const abRatio = abUnavailable ? '-' : ab.error ? '?' : ab.abuse_score !== undefined ? `${ab.abuse_score}%` : '-';
    const ports = Array.isArray(sh.ports)?sh.ports:[];
    const lastSeen = vt.last_analysis_date||vt.last_seen||ab.last_reported_at||sh.last_update||sh.last_seen||'-';
    const score=iocRiskScore(r);
    const addedAt=resultAddedAt(r);
    const sourceRows=[
      iocSourceRow({
        name:'VirusTotal',icon:'VT',verdict:vt.error||vt.verdict||r.verdict,summary:vtSummary,
        confidence:vtRatio,asn:vt.asn,isp:vt.as_owner,country:vt.country,lastSeen:formatIOCDate(vt.last_analysis_date||vt.last_seen),
        labels:[...(vt.tags||[]),vt.popular_threat_label||vt.threat_label||vt.label].filter(Boolean),link:vt.link,unavailable:vtUnavailable,error:vt.error,
        extraDetails:renderVTExtraDetails(vt)
      }),
      iocSourceRow({
        name:'AbuseIPDB',icon:'AB',verdict:ab.error||ab.verdict||'Observed',summary:ab.reason||`${ab.total_reports||0} reports`,
        confidence:abRatio,isp:ab.isp||ab.usage_type,country:ab.country_code||ab.country,lastSeen:formatIOCDate(ab.last_reported_at),
        labels:[ab.is_tor?'Tor Exit':'',ab.usage_type].filter(Boolean),link:ab.link,unavailable:abUnavailable,error:ab.error
      }),
      iocSourceRow({
        name:'Shodan',icon:'SH',verdict:sh.error||((ports.length||sh.vulns?.length)?'Suspicious':'Informational'),summary:sh.reason||`${ports.length} open port${ports.length===1?'':'s'}`,
        confidence:ports.length?`${ports.length} service${ports.length===1?'':'s'}`:'-',asn:sh.asn,isp:sh.org,country:[sh.city,sh.country_name||sh.country].filter(Boolean).join(', '),
        ports, lastSeen:formatIOCDate(sh.last_update||sh.last_seen), labels:[sh.os,...(sh.hostnames||[]),...(sh.vulns||[])].filter(Boolean),link:sh.link,unavailable:shUnavailable,error:sh.error
      })
    ].join('');
    const publicIntel = r.type==='ip'
      ? [ipwhois.city, ipwhois.region, ipwhois.country, ipwhois.connection?.org].filter(Boolean).join(' - ')
      : [rdap.registrar, ...(rdap.nameservers||[])].filter(Boolean).slice(0,3).join(' - ');
    return `<div class="ioc-result-card ioc-card-${sourceVerdictClass(r.verdict)}">
      <div class="ioc-rhead">
        <div class="ioc-title-wrap">
          <span class="ioc-etype ioc-etype-${escapeHTML(r.type)}">${escapeHTML(String(r.type||'unknown').toUpperCase())}</span>
          <div><div class="ioc-rval">${escapeHTML(r.value)}</div><div class="ioc-added-time">${escapeHTML(formatIOCTime(addedAt))}</div></div>
        </div>
        <div class="ioc-risk-wrap">
          <span class="verdict-badge ${vc}">${escapeHTML(String(r.verdict||'unknown').toUpperCase())}</span>
          <span class="ioc-risk-score">Risk Score: ${score}/100</span>
        </div>
      </div>
      <div class="ioc-summary-box"><div class="ioc-summary-text">${escapeHTML(r.summary||'No summary available')}</div></div>
      <div class="ioc-source-table">
        <div class="ioc-source-table-head"><span>Source</span><span>Summary</span><span>Details</span></div>
        ${sourceRows}
      </div>
      <details class="ioc-detail-drawer">
        <summary>Expand details</summary>
        ${renderIOCPriority(r.priority||{})}
        ${renderIOCKeyFacts(r.key_facts||[])}
        ${renderIOCRiskReasons(r.risk_reasons||[])}
        ${publicIntel?`<div class="ioc-public-intel"><span>${escapeHTML(r.type==='ip'?'Public Intel':'RDAP')}</span>${escapeHTML(publicIntel)}</div>`:''}
        ${renderLocalContextBlock(local,r.related_observables||[])}
        ${renderIOCSourceCoverage(r.source_coverage||[])}
        ${renderIOCActions(r.recommended_actions||[])}
      </details>
    </div>`;
  }).join('');
}

// Init
document.addEventListener('DOMContentLoaded',()=>{
  buildMitre();
  initIOCAPIKeyPersistence();
  if(document.getElementById('page-dashboard')?.classList.contains('active'))loadDash();
  events=['2024-01-15 08:23:11 EventCode=4625 Account=admin FailureCount=52 IP=185.220.101.45','2024-01-15 08:31:44 EventCode=4624 Account=admin IP=185.220.101.45 LogonType=3'];
  renderEvs();
  document.getElementById('chat-in').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendChat();}});
});

