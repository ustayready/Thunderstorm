/* ============================================================================
   Blaze Lite — self-contained, offline attack-path viewer.
   Ports the graph section of Blaze's /engagements page + the server-side
   ingest/explore/export/report logic (RAGELens engagement_ingest.py) into the
   browser. Loads a Thunderstorm engagement (graph.rage.ndjson, a legacy
   graph/*.ndjson zip, or a raw .ndjson) entirely client-side.
   ============================================================================ */
'use strict';

/* RAGE spec_version this viewer is built for. A graph stamped with a different
   version may not render correctly — the custody panel warns rather than guessing. */
const SUPPORTED_RAGE = '0.1';

/* ---------- tiny helpers ---------- */
const $ = id => document.getElementById(id);
const esc = s => (s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let __toastTimer;
window.toast = function(msg, bad){ const t=$('toast'); if(!t) return;
  t.textContent=(bad?'✕ ':'✓ ')+msg; t.style.borderLeftColor=bad?'var(--red)':'var(--lime)';
  t.classList.add('show'); clearTimeout(__toastTimer); __toastTimer=setTimeout(()=>t.classList.remove('show'),1600); };

/* ============================================================================
   MODEL CONSTANTS  (mirror engagement_ingest.py)
   ============================================================================ */
// node-class palette (from engagements.html) — drives coloring/clustering
const IDENTITY=['HumanIdentity','Role','Group','FederatedIdentity','ServiceIdentity','ApplicationIdentity','ServiceAccount','WorkloadIdentity','Everyone'];
const SENSITIVE=['ObjectStorage','NoSQLDatabase','RelationalDatabase','Secret','EncryptionKey','SigningKey','Queue','Topic','DataWarehouse','Dataset','Cache','FileStorage','BlockStorage'];
const COMPUTE=['ServerlessFunction','VirtualMachine','Compute','ContainerService','ContainerCluster','ContainerRegistry','KubernetesCluster','BuildWorker','BatchJob'];
function nodeClass(nt){ if(IDENTITY.includes(nt))return'identity'; if(SENSITIVE.includes(nt))return'sensitive'; if(COMPUTE.includes(nt))return'compute'; return'env'; }
const CLASS_COLOR={ identity:'#33C7E0', sensitive:'#FF2D55', compute:'#F5A623', env:'#64748B' };

// pathfinding-relevant type sets (mirror python IDENTITY_TYPES / HIGH_VALUE_TYPES)
const IDENTITY_TYPES=new Set(['HumanIdentity','Role','Group','FederatedIdentity','ServiceIdentity','ApplicationIdentity','WorkloadIdentity','ServiceAccount','Everyone']);
const HIGH_VALUE_TYPES=new Set(['Secret','EncryptionKey','SigningKey','Organization']);
const MAX_DISPLAY_NODES=500, MAX_DISPLAY_EDGES=1000, MAX_PRINCIPALS=400, MAX_OBJECTIVES=40;
const SEV_RANK={critical:0,high:1,medium:2,low:3,'':4};
const B64_LOCATION_HINTS=['userdata','consoleoutput','getconsoleoutput','payload.data','privatekeydata','publickeydata','pubsubmessage.data','decrypt.plaintext','customdata'];
const NODE_TYPE_HELP={
  HumanIdentity:"An IAM user — a long-lived principal with its own credentials.",
  Role:"An IAM role — assumable by principals or services; grants temporary credentials when assumed.",
  Group:"An IAM group — a collection of users; policies attached here apply to every member.",
  ServiceIdentity:"A service/service-linked identity that acts on your behalf.",
  FederatedIdentity:"An external/federated identity (OIDC / SAML / Cognito) mapped to cloud access.",
  ApplicationIdentity:"An application identity (e.g. a Cognito app client / workload).",
  ServiceAccount:"A GCP service account — a non-human identity that workloads run as.",
  Service:"A cloud service principal. Assumes roles to act on your behalf — not attacker-controllable.",
  Everyone:"The public / any principal ('*') — an anonymous or unrestricted grant.",
  Secret:"A stored secret (Secrets Manager / SSM SecureString / Secret Manager).",
  EncryptionKey:"A KMS key used to encrypt/decrypt data.",
  SigningKey:"A KMS asymmetric / signing key.",
  ObjectStorage:"An object-storage bucket.",
  NoSQLDatabase:"A NoSQL datastore.",
  ServerlessFunction:"A serverless function — runs code as its execution role.",
  VirtualMachine:"A compute instance.",
  Topic:"A pub/sub topic.", Queue:"A message queue.",
  Organization:"An organization / OU — org-level control.",
};

/* ============================================================================
   ENGAGEMENT STATE
   ============================================================================ */
// ENG mirrors the Python Engagement object the ported functions operate on.
let ENG=null;                 // {enid,name,provider,created_at,caller_arn,scopes,manifest,nodes,edges,hits,surfaces}
let NODE_MAP=new Map();       // node_id -> node record (incl. synthesized External placeholders)

/* ---------- ndjson bucketing (mirror _materialize_rage) ---------- */
function classifyRecord(rec){
  const k=rec.kind;
  if(k) return k;                                   // RAGE single-file: kind-tagged
  if(rec.edge_id || (rec.source && rec.target)) return 'edge';
  if(rec.node_id) return 'node';
  if(rec.access_mode!==undefined) return 'surface';
  if(rec.resource_id!==undefined || rec.value!==undefined || rec.value_ref!==undefined) return 'finding';
  return '';
}
function parseNdjson(text, buckets){
  for(const line of text.split('\n')){
    const s=line.trim(); if(!s) continue;
    let rec; try{ rec=JSON.parse(s); }catch(e){ continue; }
    const k=classifyRecord(rec);
    if(k==='node') buckets.node.push(rec);
    else if(k==='edge') buckets.edge.push(rec);
    else if(k==='path') buckets.path.push(rec);
    else if(k==='finding') buckets.finding.push(rec);
    else if(k==='surface') buckets.surface.push(rec);
    else if(k==='manifest') buckets.manifest=rec;
  }
}
function emptyBuckets(){ return {node:[],edge:[],path:[],finding:[],surface:[],manifest:null}; }

/* ---------- zip reader: central-directory parse + DecompressionStream ---------- */
async function inflateRaw(bytes){
  if(typeof DecompressionStream==='undefined')
    throw new Error('this browser lacks DecompressionStream — pass a .ndjson, or use `thunderstorm view --in`');
  const ds=new DecompressionStream('deflate-raw');
  const stream=new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function parseZip(u8){
  const dv=new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  // locate End Of Central Directory (0x06054b50), scanning back from the tail
  let eocd=-1;
  for(let i=u8.length-22; i>=0 && i>u8.length-22-65536; i--){ if(dv.getUint32(i,true)===0x06054b50){ eocd=i; break; } }
  if(eocd<0) throw new Error('not a valid zip (no EOCD)');
  const count=dv.getUint16(eocd+10,true);
  let off=dv.getUint32(eocd+16,true);
  const dec=new TextDecoder('utf-8');
  const out={};
  for(let n=0; n<count; n++){
    if(dv.getUint32(off,true)!==0x02014b50) break;             // central dir header
    const method=dv.getUint16(off+10,true);
    const compSize=dv.getUint32(off+20,true);
    const nameLen=dv.getUint16(off+28,true);
    const extraLen=dv.getUint16(off+30,true);
    const commentLen=dv.getUint16(off+32,true);
    const localOff=dv.getUint32(off+42,true);
    const name=dec.decode(u8.subarray(off+46, off+46+nameLen));
    // jump to the local file header to compute the true data offset
    if(dv.getUint32(localOff,true)===0x04034b50){
      const lNameLen=dv.getUint16(localOff+26,true);
      const lExtraLen=dv.getUint16(localOff+28,true);
      const dataStart=localOff+30+lNameLen+lExtraLen;
      const comp=u8.subarray(dataStart, dataStart+compSize);
      let raw;
      if(method===0) raw=comp;                                 // stored
      else if(method===8) raw=await inflateRaw(comp);          // deflate
      else throw new Error('unsupported zip compression method '+method+' for '+name);
      out[name]=dec.decode(raw);
    }
    off+=46+nameLen+extraLen+commentLen;
  }
  return out;
}

/* ---------- assemble ENG from a loaded payload ---------- */
function buildEngagement(fileName, buckets){
  const enid=(fileName||'engagement').replace(/\.(ndjson|zip|json)$/i,'').replace(/\.rage$/i,'');
  const m=buckets.manifest||{};
  const scope=m.scope||{};
  const provider=String(m.provider||scope.provider||(buckets.node[0]&&buckets.node[0].provider)||'').toLowerCase();
  const caller=String(m.caller_arn||scope.caller_arn||scope.foothold||'');
  ENG={
    enid, name:String(m.name||''), provider,
    created_at:String(m.created_at||''),
    caller_arn:caller,
    scopes:Array.isArray(m.scopes)?m.scopes:[],
    manifest:m,
    nodes:buckets.node, edges:buckets.edge, paths:buckets.path,
    hits:buckets.finding, surfaces:buckets.surface,
  };
  ensureFootholds(ENG);           // synthesize/mark the collector identity node
  NODE_MAP=nodeIndex(ENG);
}

/* ============================================================================
   GRAPH MODEL  (ports of engagement_ingest.py)
   ============================================================================ */
function label(node){
  const a=(node&&node.attributes)||{};
  if(a.alias) return String(a.alias).replace('alias/','');
  if(a.displayName) return String(a.displayName);
  const raw=String((node&&(node.node_id||node.arn||node.node_type))||'');
  const seg=raw.split('|').pop().replace(/\/+$/,'').split('/').pop();
  return seg||raw;
}
function kindOf(node){
  const parts=String((node&&node.node_id)||'').split('|');
  if(parts.length>=3 && parts[2].includes(':')) return parts[2];
  return String((node&&node.node_type)||'');
}
function nodeIndex(eng){
  const nm=new Map();
  for(const n of eng.nodes){ if(n.node_id) nm.set(String(n.node_id), n); }
  for(const e of eng.edges){
    for(const ep of [e.source, e.target]){
      if(ep && !nm.has(String(ep))) nm.set(String(ep), {node_id:String(ep), node_type:'External', provider:eng.provider});
    }
  }
  return nm;
}
function nodeList(eng){
  const items=[];
  for(const [nid,n] of nodeIndex(eng)){
    const k=kindOf(n);
    if(k.includes('account:region') || n.node_type==='External') continue;
    items.push({id:nid, label:label(n), node_type:String(n.node_type||'Unknown'), kind:k});
  }
  items.sort((a,b)=>{
    const ai=IDENTITY_TYPES.has(a.node_type)?0:1, bi=IDENTITY_TYPES.has(b.node_type)?0:1;
    return ai-bi || a.node_type.localeCompare(b.node_type) || a.label.toLowerCase().localeCompare(b.label.toLowerCase());
  });
  return items;
}
const isAttackEdge = e => String(e.relationship_kind)!=='STRUCTURAL';
function edgeOk(e, includeConditional, attackOnly){
  if(e.state==='CONDITIONAL' && !includeConditional) return false;
  if(attackOnly && !isAttackEdge(e)) return false;
  return true;
}
function adjacency(edges, includeConditional, attackOnly, excludeSources){
  excludeSources=excludeSources||new Set();
  const forward=new Map(), backward=new Map();
  for(const e of edges){
    if(!edgeOk(e, includeConditional, attackOnly)) continue;
    const src=String(e.source), dst=String(e.target);
    if(excludeSources.has(src)) continue;
    (forward.get(src)||forward.set(src,[]).get(src)).push(e);
    (backward.get(dst)||backward.set(dst,[]).get(dst)).push(e);
  }
  return {forward, backward};
}
function bfs(adj, starts, nextNode, maxHops){
  const seen=new Set(starts); let frontier=new Set(starts); let hops=0;
  while(frontier.size && hops<maxHops){
    const nxt=new Set();
    for(const node of frontier) for(const e of (adj.get(node)||[])){
      const other=nextNode(e); if(!seen.has(other)){ seen.add(other); nxt.add(other); }
    }
    frontier=nxt; hops++;
  }
  return seen;
}
function bfsDepth(adj, starts, nextNode, maxHops){
  const depth=new Map(); for(const s of starts) depth.set(s,0);
  let frontier=new Set(starts); let hops=0;
  while(frontier.size && hops<maxHops){
    const nxt=new Set();
    for(const node of frontier) for(const e of (adj.get(node)||[])){
      const other=nextNode(e); if(!depth.has(other)){ depth.set(other, hops+1); nxt.add(other); }
    }
    frontier=nxt; hops++;
  }
  return depth;
}
// min-priority queue via simple array (graphs here are modest) — Dijkstra by weight
function dijkstra(forward, source, maxHops){
  const dist=new Map([[source,0]]); const prev=new Map();
  const pq=[[0,0,source]];                        // [cost, hops, node]
  while(pq.length){
    let bi=0; for(let i=1;i<pq.length;i++){ if(pq[i][0]<pq[bi][0]) bi=i; }
    const [cost,hops,node]=pq.splice(bi,1)[0];
    if(hops>=maxHops) continue;
    for(const e of (forward.get(node)||[])){
      const nxt=String(e.target); const nd=cost+(Number(e.weight)||1);
      if(!dist.has(nxt) || nd<dist.get(nxt)){ dist.set(nxt,nd); prev.set(nxt,e); pq.push([nd,hops+1,nxt]); }
    }
  }
  return {dist, prev};
}
function shortest(forward, source, targets, maxHops){
  if(!targets || !targets.size) return [];
  // Dijkstra but stop at first target reached (mirrors python _shortest early break)
  const dist=new Map([[source,0]]); const prev=new Map();
  const pq=[[0,0,source]]; let hit=null;
  while(pq.length){
    let bi=0; for(let i=1;i<pq.length;i++){ if(pq[i][0]<pq[bi][0]) bi=i; }
    const [cost,hops,node]=pq.splice(bi,1)[0];
    if(targets.has(node) && node!==source){ hit=node; break; }
    if(hops>=maxHops) continue;
    for(const e of (forward.get(node)||[])){
      const nxt=String(e.target); const nd=cost+(Number(e.weight)||1);
      if(!dist.has(nxt) || nd<dist.get(nxt)){ dist.set(nxt,nd); prev.set(nxt,e); pq.push([nd,hops+1,nxt]); }
    }
  }
  if(hit==null) return [];
  const chain=[]; let cur=hit;
  while(cur!==source){ const e=prev.get(cur); if(!e) return []; chain.push(e); cur=String(e.source); }
  chain.reverse(); return chain;
}
function shortestToEach(forward, source, targets, maxHops){
  const {prev}=dijkstra(forward, source, maxHops);
  const edges=[]; const seen=new Set();
  for(const t of targets){
    let cur=t;
    while(prev.has(cur) && cur!==source){
      const e=prev.get(cur); const eid=String(e.edge_id);
      if(!seen.has(eid)){ seen.add(eid); edges.push(e); }
      cur=String(e.source);
    }
  }
  return edges;
}
function resolveTargets(nm, to){
  if(!to) return new Set();
  if(to.startsWith('type:')){ const want=to.slice(5); const s=new Set();
    for(const [nid,n] of nm) if(String(n.node_type)===want) s.add(nid); return s; }
  return nm.has(to)?new Set([to]):new Set();
}
function isAdmin(node){
  const blob=(String(node.arn||'')+' '+String(node.node_id||'')).toLowerCase().replace(/ /g,'');
  return blob.includes('admin')||blob.endsWith(':root')||blob.includes('administratoraccess')||blob.includes('/root');
}
function adminIdentities(nm, edges){
  const admins=new Set();
  for(const [nid,n] of nm) if(isAdmin(n)&&IDENTITY_TYPES.has(String(n.node_type))) admins.add(nid);
  for(const e of edges){
    const src=String(e.source||''), tgt=String(e.target||'').toLowerCase(), typ=String(e.type);
    if(!nm.has(src)||!IDENTITY_TYPES.has(String(nm.get(src).node_type))) continue;
    if(typ==='HasPolicy'&&tgt.includes('administratoraccess')) admins.add(src);
    else if(typ==='MemberOf'&&tgt.includes('admin')) admins.add(src);
  }
  return admins;
}
function presetTargets(nm, preset, edges){
  if(preset==='admin') return adminIdentities(nm, edges);
  if(preset==='high_value'){ const s=adminIdentities(nm, edges);
    for(const [nid,n] of nm) if(HIGH_VALUE_TYPES.has(String(n.node_type))) s.add(nid); return s; }
  return new Set();
}

/* ---------- foothold resolution (mirror _ensure_footholds / foothold_node) ---------- */
function nodeAccount(nid){ const p=String(nid).split('|'); return p.length>=2?p[1]:''; }
function gcpProjectOf(caller){
  if(caller.includes('@') && caller.includes('.iam.gserviceaccount.com'))
    return caller.split('@')[1].split('.iam.gserviceaccount.com')[0];
  return '';
}
function gcpFootholdRealm(caller){
  if(!caller.includes('@')) return 'external';
  const domain=caller.split('@')[1];
  if(caller.endsWith('gserviceaccount.com')){
    if(domain.endsWith('.iam.gserviceaccount.com')) return domain.slice(0, -'.iam.gserviceaccount.com'.length);
    return 'external';
  }
  return domain;
}
function normIdentity(s){
  s=s.toLowerCase().trim(); if(s.includes('@')) s=s.split('@')[0];
  for(const ch of '._-/\\') s=s.split(ch).join(' ');
  return s.split(/\s+/).filter(Boolean).join(' ');
}
function footholdNode(eng, caller, account){
  caller = caller!==undefined ? caller : eng.caller_arn;
  if(!caller) return '';
  const nm=nodeIndex(eng);
  const acct = account || gcpProjectOf(caller);
  const inScope = nid => !acct || nodeAccount(nid)===acct;
  const idValues = n => { const a=n.attributes||{};
    return [n.arn,a.userPrincipalName,a.upn,a.principalId,a.objectId,a.mail,a.id].filter(Boolean).map(String); };
  // 0) caller may already BE a node id (RAGE scope.foothold)
  if(nm.has(caller) && inScope(caller)) return caller;
  // 1) exact match on any identity field or the id's native segment
  for(const [nid,n] of nm) if(inScope(nid) && (idValues(n).includes(caller) || nid.split('|').pop()===caller)) return nid;
  // 2) assumed-role session -> the underlying role node
  if(caller.includes(':assumed-role/')){
    const role=caller.split(':assumed-role/')[1].split('/')[0];
    for(const [nid,n] of nm) if(inScope(nid)&&String(n.node_type)==='Role'&&String(n.arn||'').endsWith(':role/'+role)) return nid;
  }
  // 3) substring: caller (or its tail) embedded in a node arn
  const name=caller.replace(/\/+$/,'').split('/').pop();
  for(const [nid,n] of nm){ if(!inScope(nid)) continue; const arn=String(n.arn||'');
    if(arn && (arn.includes(caller) || (name && name!==caller && arn.includes(name)))) return nid; }
  // 4) normalized-name fallback
  const cn=normIdentity(caller);
  if(cn) for(const [nid,n] of nm){ if(!inScope(nid)) continue; const a=n.attributes||{};
    const lbl=normIdentity(String(a.displayName||n.label||'')); if(lbl&&lbl===cn) return nid; }
  return '';
}
function ensureFootholds(eng){
  const seeds=[];
  for(const sc of (eng.scopes||[])){ const c=String(sc.caller_arn||'').trim();
    if(c) seeds.push([String(sc.provider||eng.provider), c, String(sc.account||'')]); }
  if((eng.caller_arn||'').trim()) seeds.push([eng.provider, eng.caller_arn.trim(), String((eng.manifest&&eng.manifest.account)||'')]);
  const have=new Set(eng.nodes.map(n=>String(n.node_id)));
  for(const [provider,caller,account] of seeds){
    const existing = (have.has(caller)?caller:null) || footholdNode(eng, caller, account||undefined);
    if(existing){
      for(const n of eng.nodes) if(String(n.node_id)===existing){
        n.attributes=n.attributes||{}; n.attributes.foothold=true; n.attributes.collector_identity=true; }
      continue;
    }
    if(provider!=='gcp' && !caller.includes('gserviceaccount.com')) continue;
    const realm=gcpFootholdRealm(caller);
    const isSA=caller.endsWith('gserviceaccount.com');
    const rt=isSA?'gcp:iam:service-account':'gcp:iam:user';
    const nt=isSA?'ServiceAccount':'HumanIdentity';
    const nid=`gcp|${realm}|${rt}|${caller}`;
    if(have.has(nid)) continue;
    have.add(nid);
    eng.nodes.push({node_id:nid, node_type:nt, provider:'gcp', account:realm, arn:caller,
      attributes:{synthesized:true, foothold:true, collector_identity:true}});
  }
}

/* ---------- explore: the master query (mirror engagement_ingest.explore) ---------- */
function exploreQuery(opts){
  const source=opts.from||'', to=opts.to||'', mode=opts.mode||'all', preset=opts.preset||'';
  const includeConditional=!!opts.conditional, attackOnly=!opts.structural, force=!!opts.force;
  const maxHops=Math.max(1, Math.min(20, opts.max_hops||12));
  const nm=NODE_MAP;
  const excludeSources = attackOnly
    ? new Set([...nm].filter(([,n])=>String(n.node_type)==='Service').map(([nid])=>nid))
    : new Set();
  const {forward, backward}=adjacency(ENG.edges, includeConditional, attackOnly, excludeSources);
  let pathEdges=[], targets=new Set(), message='', root=source, layer=null, keep=new Set();
  let forwardSet=null, backwardSet=null;

  if(mode==='all'){ keep=new Set([...forward.keys(), ...backward.keys()]); root=''; }
  else if(mode==='preset'){
    targets=presetTargets(nm, preset, ENG.edges);
    if(!targets.size) return {error:`no ${preset||'preset'} targets in this engagement`, nodes:[], edges:[], path_edge_ids:[]};
    if(source && nm.has(source)){
      const reach=bfs(forward, new Set([source]), e=>String(e.target), maxHops);
      let reachable=new Set([...targets].filter(t=>reach.has(t)));
      if(reachable.size>MAX_OBJECTIVES){ const arr=[...reachable].sort().slice(0,MAX_OBJECTIVES);
        message=`showing ${MAX_OBJECTIVES} of ${reachable.size} ${preset} targets`; reachable=new Set(arr); }
      pathEdges=shortestToEach(forward, source, reachable, maxHops);
      keep=new Set([source]); for(const e of pathEdges){ keep.add(String(e.source)); keep.add(String(e.target)); }
      targets=reachable;
    } else {
      const selfAccount=String((ENG.manifest&&ENG.manifest.account)||'');
      let sources=[...nm].filter(([,n])=>IDENTITY_TYPES.has(String(n.node_type)) && (!selfAccount||String(n.account)===selfAccount)).map(([nid])=>nid);
      if(sources.length>MAX_PRINCIPALS){ sources=sources.slice(0,MAX_PRINCIPALS); message=`evaluated first ${MAX_PRINCIPALS} identities`; }
      keep=new Set(); const seenEdge=new Set();
      for(const principal of sources){ if(targets.has(principal)) continue;
        const chain=shortest(forward, principal, targets, maxHops);
        for(const e of chain){ keep.add(String(e.source)); keep.add(String(e.target));
          if(!seenEdge.has(String(e.edge_id))){ seenEdge.add(String(e.edge_id)); pathEdges.push(e); } } }
      root='';
    }
    if(!pathEdges.length) message=`no attack path to ${preset} found within ${maxHops} hops`;
  }
  else if(mode==='reaches'){
    targets=resolveTargets(nm, to);
    if(!targets.size) return {error:'pick a destination to see who can reach it', nodes:[], edges:[], path_edge_ids:[]};
    keep=bfs(backward, targets, e=>String(e.source), maxHops); for(const t of targets) keep.add(t); root='';
  }
  else if(mode==='path'){
    if(!source||!nm.has(source)) return {error:'pick a start node', nodes:[], edges:[], path_edge_ids:[]};
    targets=resolveTargets(nm, to);
    if(!targets.size) return {error:'pick a destination', nodes:[], edges:[], path_edge_ids:[]};
    forwardSet=bfs(forward, new Set([source]), e=>String(e.target), maxHops);
    backwardSet=bfs(backward, targets, e=>String(e.source), maxHops);
    keep=new Set([...forwardSet].filter(x=>backwardSet.has(x))); keep.add(source);
    for(const t of targets) if(forwardSet.has(t)) keep.add(t);
    pathEdges=shortest(forward, source, new Set([...targets].filter(t=>forwardSet.has(t))), maxHops);
    if(!pathEdges.length) message='no path found within the hop limit';
  }
  else { // 'reachable' (default from a foothold): layered forward view
    if(!source||!nm.has(source)) return {error:'pick a start node', nodes:[], edges:[], path_edge_ids:[]};
    layer=bfsDepth(forward, new Set([source]), e=>String(e.target), maxHops);
    keep=new Set(layer.keys());
  }

  const pathIds=new Set(pathEdges.map(e=>String(e.edge_id)));
  const pathOnly = mode==='preset';
  let subEdges;
  if(mode==='path'){
    subEdges=ENG.edges.filter(e=> edgeOk(e,includeConditional,attackOnly)
      && !excludeSources.has(String(e.source))
      && forwardSet.has(String(e.source)) && backwardSet.has(String(e.target)));
  } else if(pathOnly){
    subEdges=pathEdges.slice();
  } else {
    subEdges=ENG.edges.filter(e=> edgeOk(e,includeConditional,attackOnly)
      && !excludeSources.has(String(e.source))
      && keep.has(String(e.source)) && keep.has(String(e.target))
      && (layer===null || layer.get(String(e.target))===(layer.get(String(e.source))??-99)+1));
  }
  const used=new Set(); for(const e of subEdges){ used.add(String(e.source)); used.add(String(e.target)); }
  if(root) used.add(root);

  if(!force && (subEdges.length>MAX_DISPLAY_EDGES || used.size>MAX_DISPLAY_NODES)){
    return {too_dense:true, nodes:[], edges:[], path_edge_ids:[...pathIds].sort(), root,
      counts:{nodes:used.size, edges:subEdges.length, path_hops:pathEdges.length},
      message:`${used.size} nodes / ${subEdges.length} edges — too dense to draw. Refine: set a destination or lower the hop count.`};
  }

  const narratives=new Map(ENG.edges.map(e=>[String(e.edge_id), String(e.narrative||'')]));
  const nodes=[...used].filter(k=>nm.has(k)).map(k=>{ const n=nm.get(k);
    return {data:{id:k, label:label(n), node_type:String(n.node_type||'Unknown'),
      provider:n.provider||ENG.provider, account:n.account||'', attributes:n.attributes||{},
      root:k===root, objective:targets.has(k)}}; });
  const edges=subEdges.map(e=>{ const d={id:String(e.edge_id), on_path:pathIds.has(String(e.edge_id)),
      via:(e.evidence && !Array.isArray(e.evidence) ? (e.evidence.via||'') : ''),
      derived_chain:(e.derived_from||[]).map(r=>narratives.get(String(r))||String(r))};
    for(const c of ['source','target','type','nature','state','weight','narrative','permissions','conditions','derived_from','confidence']) d[c]=e[c];
    return {data:d}; });
  return {nodes, edges, path_edge_ids:[...pathIds].sort(), root:source,
    counts:{nodes:nodes.length, edges:edges.length, path_hops:pathEdges.length}, message};
}

/* ---------- node detail (mirror node_detail) ---------- */
function nodeDetail(nodeId){
  const nm=NODE_MAP; const n=nm.get(nodeId); if(!n) return {error:'unknown node'};
  const brief=(e,otherKey)=>{ const oid=String(e[otherKey]); const other=nm.get(oid)||{node_id:oid};
    return {type:e.type, other_id:oid, other_label:label(other), other_type:String(other.node_type||''),
      permissions:e.permissions||[], state:e.state, nature:e.nature, narrative:e.narrative||''}; };
  const outbound=[], inbound=[], grants=[];
  for(const e of ENG.edges){ const src=String(e.source), tgt=String(e.target);
    if(src===nodeId){ (isAttackEdge(e)?outbound:grants).push(brief(e,'target')); }
    else if(tgt===nodeId && isAttackEdge(e)){ inbound.push(brief(e,'source')); } }
  for(const lst of [outbound,inbound,grants]) lst.sort((a,b)=>String(a.type).localeCompare(String(b.type))||a.other_label.localeCompare(b.other_label));
  const nt=String(n.node_type||'Unknown');
  return {id:nodeId, label:label(n), node_type:nt, type_help:NODE_TYPE_HELP[nt]||'', resource_type:kindOf(n),
    account:n.account||'', provider:n.provider||ENG.provider, attributes:n.attributes||{},
    outbound, inbound, grants, counts:{outbound:outbound.length, inbound:inbound.length, grants:grants.length}};
}

/* ---------- exposures / leaks (mirror exposures) ---------- */
function decodeB64Field(value, location){
  const loc=(location||'').toLowerCase();
  if(!value || !B64_LOCATION_HINTS.some(h=>loc.includes(h))) return [value,false];
  try{ const bin=atob(value); const bytes=Uint8Array.from(bin,c=>c.charCodeAt(0));
    const txt=new TextDecoder('utf-8',{fatal:true}).decode(bytes); return [txt,true];
  }catch(e){ return [value,false]; }   // gzip'd payloads left as-is (rare)
}
function preview(value,n){ n=n||110; if(!value) return ''; const one=value.split(/\s+/).join(' ');
  return one.length<=n?one:one.slice(0,n)+'…'; }
function fallbackPreview(ref){ if(ref&&ref.includes('…')) return '…'+ref.split('…')[1]+' (re-scan to capture the full value)';
  return '(value not captured — re-scan to reveal)'; }
function getLeakValue(valueRef){
  for(const h of ENG.hits) if(String(h.value_ref||'')===valueRef){
    const raw=String(h.value||''); const loc=String(h.location||''); const [disp,decoded]=decodeB64Field(raw,loc);
    return {value:disp, has_value:!!raw, location:loc, decoded, length:disp.length, value_ref:valueRef}; }
  return {value:'', has_value:false, error:'leak not found'};
}
const PUBLIC_VERB={ CanInvoke:['critical','anyone can invoke this (public/unauthenticated)'],
  CanReadData:['critical','anyone can read this data (public)'], CanReadSecret:['critical','anyone can read this secret (public)'],
  CanControl:['critical','anyone can control this resource (public)'] };
function exposuresList(foothold){
  const nm=NODE_MAP; const byRef=new Map();
  for(const [nid,n] of nm){ if(!byRef.has(nid)) byRef.set(nid,nid);
    if(n.arn && !byRef.has(String(n.arn))) byRef.set(String(n.arn),nid);
    const tail=nid.split('|').pop(); if(!byRef.has(tail)) byRef.set(tail,nid); }
  const resolveRef=rid=>byRef.get(rid)||'';
  let reachable=new Set();
  if(foothold){ const {forward}=adjacency(ENG.edges,true,true); reachable=bfs(forward,new Set([foothold]),e=>String(e.target),20); }
  const seen=new Set(); const items=[];
  const add=(kind,nodeId,severity,detail,evidence,lbl,always)=>{ const node=nodeId?(nm.get(nodeId)||{}):{};
    if(!lbl) lbl=nodeId?(node.node_id?label(node):nodeId.split('|').pop()):'';
    if(!always && !nodeId) return;
    const key=kind+'|'+nodeId+'|'+detail+'|'+((evidence||{}).value_ref||'')+'|'+lbl;
    if(seen.has(key)) return; seen.add(key);
    items.push({kind, node_id:nodeId, label:lbl||'(no specific resource)',
      node_type:String(node.node_type||(kind==='credential'?'Confirmed leak':'Unknown')),
      severity:String(severity||'').toLowerCase(), detail, reachable:!!nodeId&&reachable.has(nodeId),
      resolved:!!nodeId, evidence:evidence||{}}); };
  for(const h of ENG.hits){ const rid=String(h.resource_id||'');
    const nodeId = (rid&&rid!=='(self-enumerated)')?resolveRef(rid):'';
    const loc=String(h.location||'');
    const lbl = nodeId?'':(loc.split('.')[0].split('/').pop()||String(h.emits_hint||'leak'));
    const raw=String(h.value||''); const ref=String(h.value_ref||'');
    const [disp,decoded]=decodeB64Field(raw,loc);
    add('credential', nodeId, String(h.severity||'high'), loc||String(h.emits_hint||'credential'),
      {preview:disp?preview(disp):fallbackPreview(ref), has_value:!!raw, decoded, value_ref:ref, location:loc,
       site_id:String(h.site_id||''), emits_hint:String(h.emits_hint||''), resource_id:rid}, lbl, true); }
  for(const e of ENG.edges){ const typ=String(e.type); const src=String(e.source), tgt=String(e.target);
    if(String((nm.get(src)||{}).node_type)==='Everyone' && e.state==='ACTIVE'){
      const [sev,verb]=PUBLIC_VERB[typ]||['high','public '+typ]; add('public',tgt,sev,verb); continue; }
    if(typ==='ExposedToInternet'){ const ev=e.evidence||{};
      add('internet',src,String(ev.severity||'high'),String(ev.exposure||'reachable from the internet')); }
    else if(typ==='CrossAccountTrust'){
      if(tgt.includes('principal:*')&&e.state==='ACTIVE') add('public',src,'critical','resource policy grants to Everyone (public)');
      else if(!tgt.includes('principal:*')) add('cross_account',src,'medium','resource policy grants to another account'); } }
  items.sort((a,b)=>(SEV_RANK[a.severity]??4)-(SEV_RANK[b.severity]??4) || (a.reachable===b.reachable?0:a.reachable?-1:1) || a.label.localeCompare(b.label));
  return {foothold, count:items.length, reachable_count:items.filter(x=>x.reachable).length, exposures:items};
}

/* ---------- report helpers (mirror report_paths / rank_footholds / custody) ---------- */
function shorten(nodeId, nm){ const n=nm.get(nodeId); return n?label(n):String(nodeId).split('|').pop(); }
function reportPaths(foothold, maxHops, limit){ maxHops=maxHops||12; limit=limit||40;
  const nm=NODE_MAP; if(!foothold||!nm.has(foothold)) return [];
  const {forward}=adjacency(ENG.edges,true,true);
  const reach=bfs(forward,new Set([foothold]),e=>String(e.target),maxHops);
  const objectives=[...nm].filter(([nid,n])=>(HIGH_VALUE_TYPES.has(String(n.node_type))||isAdmin(n))&&reach.has(nid)).map(([nid])=>nid);
  const paths=[];
  for(const obj of objectives.sort().slice(0,limit)){
    const chain=shortest(forward, foothold, new Set([obj]), maxHops); if(!chain.length) continue;
    let state='ACTIVE'; const steps=[];
    for(const e of chain){ if(e.state==='CONDITIONAL') state='CONDITIONAL';
      steps.push({source:shorten(String(e.source),nm), edge:String(e.type), target:shorten(String(e.target),nm),
        state:String(e.state), permissions:(e.permissions||[]).join(', '), narrative:String(e.narrative||'')}); }
    paths.push({foothold:shorten(foothold,nm), objective:shorten(obj,nm), objective_type:String(nm.get(obj).node_type),
      hops:chain.length, state, steps}); }
  paths.sort((a,b)=>(a.state==='ACTIVE'?0:1)-(b.state==='ACTIVE'?0:1) || a.hops-b.hops);
  return paths;
}
function rankFootholds(top){ top=top||25; const nm=NODE_MAP; const {forward}=adjacency(ENG.edges,true,true);
  const objectives=new Set([...nm].filter(([,n])=>HIGH_VALUE_TYPES.has(String(n.node_type))||isAdmin(n)).map(([nid])=>nid));
  const out=[];
  for(const [nid,n] of nm){ if(!IDENTITY_TYPES.has(String(n.node_type))) continue;
    const reach=bfs(forward,new Set([nid]),e=>String(e.target),20); if(!reach.size) continue;
    let crown=0; for(const r of reach) if(objectives.has(r)) crown++;
    out.push({node_id:nid, label:label(n), node_type:String(n.node_type), reaches:reach.size, crown_jewels:crown}); }
  out.sort((a,b)=>b.crown_jewels-a.crown_jewels || b.reaches-a.reaches || a.label.localeCompare(b.label));
  return out.slice(0,top);
}
function custody(){ const m=ENG.manifest||{};
  return {enid:ENG.enid, name:ENG.name, provider:ENG.provider, account:String(m.account||''),
    caller:ENG.caller_arn||String(m.caller_arn||''), collector_version:String(m.collector_version||'unknown'),
    engine_version:String(m.engine_version||'unknown'), catalog_version:String(m.catalog_contract_version||''),
    rage_version:String(m.spec_version||''),
    collected_at:ENG.created_at, counts:m.counts||{nodes:ENG.nodes.length, edges:ENG.edges.length}}; }

/* ---------- export (mirror export_findings + _to_csv/_to_markdown) ---------- */
function toCSV(rows, cols){ const q=v=>{ v=v==null?'':String(v); return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v; };
  return [cols.join(','), ...rows.map(r=>cols.map(c=>q(r[c])).join(','))].join('\n')+'\n'; }
function toMarkdown(rows, cols, title){ const out=['# '+title,'', '| '+cols.join(' | ')+' |', '| '+cols.map(()=>'---').join(' | ')+' |'];
  for(const r of rows) out.push('| '+cols.map(c=>String(r[c]==null?'':r[c]).replace(/\|/g,'\\|').replace(/\n/g,' ')).join(' | ')+' |');
  return out.join('\n')+'\n'; }
function exportFindings(what, fmt, foothold){
  foothold=foothold||footholdNode(ENG); const nm=NODE_MAP; let rows, cols;
  if(what==='reachable'){ const {forward}=adjacency(ENG.edges,true,true);
    const reach=[...bfs(forward,new Set([foothold]),e=>String(e.target),20)].sort();
    rows=reach.filter(n=>nm.has(n)).map(n=>({label:label(nm.get(n)), node_type:String(nm.get(n).node_type),
      account:String(nm.get(n).account||''), node_id:n})); cols=['label','node_type','account','node_id']; }
  else if(what==='paths'){ rows=reportPaths(foothold).map(p=>({objective:p.objective, objective_type:p.objective_type,
      hops:p.hops, state:p.state, path:p.steps.map(s=>`${s.source} -${s.edge}-> ${s.target}`).join('  →  ')}));
    cols=['objective','objective_type','hops','state','path']; }
  else { let exp=exposuresList(foothold).exposures; if(what==='leaks') exp=exp.filter(x=>x.kind==='credential');
    rows=exp.map(x=>{ const ev=x.evidence||{}; const value=x.kind==='credential'?getLeakValue(ev.value_ref||'').value:'';
      return {kind:x.kind, severity:x.severity, label:x.label, detail:x.detail, reachable:x.reachable,
        value, location:ev.location||'', node_id:x.node_id}; });
    cols=['severity','kind','label','detail','reachable','value','location','node_id']; }
  const title=`${ENG.enid} — ${what}`, fname=`${ENG.enid}-${what}`;
  if(fmt==='json') return {text:JSON.stringify({engagement:ENG.enid, what, custody:custody(), rows}, null, 2), mime:'application/json', fname:fname+'.json'};
  if(fmt==='md'||fmt==='markdown') return {text:toMarkdown(rows,cols,title), mime:'text/markdown', fname:fname+'.md'};
  return {text:toCSV(rows,cols), mime:'text/csv', fname:fname+'.csv'};
}

/* ============================================================================
   RENDER + INTERACTIONS  (ported from engagements.html)
   ============================================================================ */
let cy=null, ALLNODES=[], FOOTHOLD='', collectFoothold='', selEnd=null;
let SCOPES=[], tab='paths';
const hiddenClasses=new Set(), hiddenClusters=new Set(), hiddenScopes=new Set();
let CLUSTER_ON=true, EDGE_LABELS=true, COLLAPSE_EDGES=false;
let lastData=null, lastOpts=null, lastQueryOpts=null;
let VIEW_MODE='auto';
if (window.cytoscapeFcose) cytoscape.use(window.cytoscapeFcose);

const labelOf = id => (ALLNODES.find(n=>n.id===id)||{}).label || String(id).split('|').pop();
function accountOf(nd){ const p=String(nd.id||'').split('|'); return p.length>=2?p[1]:''; }

function serviceOf(nd){
  const parts=String(nd.id||'').split('|');
  if(parts.length>=3 && parts[2].includes(':')) return parts[2].split(':')[1] || 'other';
  if((parts[1]||'').startsWith('arn:')){ const a=parts[1].split(':'); if(a[2]) return a[2]; }
  const nt=nd.node_type||'', nat=(parts[1]||'').toLowerCase();
  if(nt==='SecurityGroup'||/^(sg-|rtb-|igw-|subnet-|vpc-|acl-|eni-|nat-|eipalloc-)/.test(nat)) return 'ec2';
  if(nt==='CIDR'||nat.includes('/')||/^\d+\.\d+\.\d+\.\d+/.test(nat)) return 'network';
  if(nt==='Service'||nat.startsWith('service:')) return 'service-principal';
  if(IDENTITY.includes(nt)) return 'iam';
  return nt ? nt.toLowerCase() : 'other';
}
function buildClusters(nodes, on){
  if(!on){ nodes.forEach(n=>{ delete n.data.parent; }); return []; }
  const parents={};
  nodes.forEach(n=>{ const svc=serviceOf(n.data); n.data.parent='cl:'+svc;
    if(!parents[svc]) parents[svc]={ data:{ id:'cl:'+svc, isCluster:true, label:svc.toUpperCase() } }; });
  return Object.values(parents);
}
function nodeHidden(nd){
  return hiddenClasses.has(nd.klass || nodeClass(nd.node_type))
      || (CLUSTER_ON && hiddenClusters.has(serviceOf(nd)))
      || hiddenScopes.has(accountOf(nd));
}
function layoutOpts(){
  if (window.cytoscapeFcose) return {
    name:'fcose', quality:'default', randomize:true, animate:true, animationDuration:260,
    fit:true, padding:90, nodeSeparation:300, idealEdgeLength:170, nodeRepulsion:34000,
    nodeDimensionsIncludeLabels:true, packComponents:true,
    gravity:0.06, gravityRange:3.8, gravityCompound:1.2, gravityRangeCompound:1.5,
    numIter:2500, tile:true, tilingPaddingVertical:32, tilingPaddingHorizontal:32 };
  return { name:'cose', animate:false, fit:true, padding:55, nodeRepulsion:420000, idealEdgeLength:95, gravity:1 };
}
function runLayout(eles){ const coll=eles||cy.elements(); const lay=coll.layout(layoutOpts());
  lay.one('layoutstop', ()=>{ if(cy.zoom()>1.15){ cy.zoom(1.15); cy.center(coll.nodes(':visible')); } }); lay.run(); }

function runExplore(opts){
  if(!ENG) return;
  lastQueryOpts=opts;
  opts=Object.assign({}, opts, {
    max_hops:parseInt($('hops').value||'6',10),
    conditional:$('cond').classList.contains('active'),
    structural:$('struct').classList.contains('active'),
  });
  const d=exploreQuery(opts);
  if(d.error){ showEmpty('Nothing to show', d.error); return; }
  if(d.too_dense){
    showEmpty('Too dense to draw', d.message, {label:`Draw anyway · ${d.counts.nodes} nodes / ${d.counts.edges} edges`,
      fn:()=>runExplore(Object.assign({}, lastQueryOpts, {force:true}))});
    setInspector(d.counts, `${d.counts.nodes} nodes / ${d.counts.edges} edges (not drawn)`, null);
    return;
  }
  if(!d.nodes.length){ showEmpty('No attack paths from here', d.message||'This foothold has no attack paths to those targets within the hop limit.'); return; }
  banner(opts.force ? '' : (d.message||'')); render(d, opts);
}
function runView(){
  if(VIEW_MODE==='all'){ document.querySelectorAll('.chip.vm').forEach(x=>x.classList.toggle('active', x.dataset.vm==='all'));
    runExplore({ mode:'all' }); return; }
  if(!FOOTHOLD){ if(cy){cy.destroy();cy=null;} showEmpty('Pick a foothold','Choose an identity or resource to explore from, or click «everything» to render the whole graph.'); return; }
  const big=ALLNODES.length>150;
  const useCrown=VIEW_MODE==='crown' || (VIEW_MODE==='auto' && big);
  document.querySelectorAll('.chip.vm').forEach(x=>x.classList.toggle('active', x.dataset.vm===(useCrown?'crown':'reachable')));
  if(useCrown){ if(VIEW_MODE==='auto') banner('large engagement — showing shortest paths to high-value targets (switch to «reachable» to see everything)');
    runExplore({ mode:'preset', preset:'high_value', from:FOOTHOLD }); }
  else runExplore({ mode:'reachable', from:FOOTHOLD });
}
let bannerTimer;
function banner(msg){ const b=$('banner'); if(!msg){b.style.display='none';return;} b.textContent='▲ '+msg; b.style.display='block';
  clearTimeout(bannerTimer); bannerTimer=setTimeout(()=>b.style.display='none',5000); }
function showEmpty(title,msg,action){
  if(cy){cy.destroy();cy=null;} $('inspector').style.display='none';
  const e=$('empty'); e.style.display='flex'; e.querySelector('h3').textContent=title; e.querySelector('p').innerHTML=esc(msg||'');
  const old=$('empty-action'); if(old) old.remove();
  if(action){ const b=document.createElement('button'); b.id='empty-action'; b.className='btn btn-primary';
    b.style.marginTop='4px'; b.textContent=action.label; b.onclick=action.fn; e.appendChild(b); }
}
function setInspector(counts, desc, nodes){
  const ins=$('inspector'); ins.style.display='block';
  $('ins-desc').textContent=desc; $('ins-n').textContent=counts.nodes; $('ins-e').textContent=counts.edges;
  const by={identity:0,sensitive:0,compute:0,env:0};
  (nodes||[]).forEach(n=>by[nodeClass(n.data.node_type)]++);
  ins.querySelectorAll('.nclass').forEach(el=>{ const k=el.dataset.klass;
    const c=el.querySelector('.cnt'); if(c) c.textContent=by[k]||0; el.classList.toggle('off', hiddenClasses.has(k)); });
  $('ins-scopes').innerHTML='';
  if(!nodes){ $('ins-clusters').innerHTML=''; return; }
  if(!CLUSTER_ON){ $('ins-clusters').innerHTML=''; return; }
  const cl={};
  nodes.forEach(n=>{ const s=serviceOf(n.data); if(!cl[s]) cl[s]={n:0,color:CLASS_COLOR[nodeClass(n.data.node_type)]}; cl[s].n++; });
  const keys=Object.keys(cl).sort();
  $('ins-clusters').innerHTML='<div class="ins-h">[ clusters · click to filter ]</div>'+
    keys.map(k=>`<div class="bk cl-row${hiddenClusters.has(k)?' off':''}" data-cl="${esc(k)}"><span class="d" style="background:${cl[k].color}"></span>${esc(k.toUpperCase())}<b>${cl[k].n}</b></div>`).join('');
  $('ins-clusters').querySelectorAll('.cl-row').forEach(el=>el.onclick=()=>{ const k=el.dataset.cl;
    if(hiddenClusters.has(k)){ hiddenClusters.delete(k); el.classList.remove('off'); } else{ hiddenClusters.add(k); el.classList.add('off'); }
    styleFilter(); relayoutVisible(); });
}

function render(d, opts){
  if(cy)cy.destroy();
  lastData=d; lastOpts=opts;
  $('empty').style.display='none';
  const pathSet=new Set(d.path_edge_ids||[]); const highlight=pathSet.size>0;
  const pathNodes=new Set(); d.edges.forEach(e=>{ if(pathSet.has(e.data.id)){pathNodes.add(e.data.source);pathNodes.add(e.data.target);} });
  const ESC_TYPES=new Set(['CanEscalateTo','CanGrantPermission','CanImpersonate','CanCreateCredentialFor','CanSignAs','CanTakeOwnership','CanResetCredential','CanAddMember','CanPassIdentity']);
  const CROWN_TYPES=new Set(['Tenant','Subscription','Project','ManagementGroup','Account','Organization']);
  d.edges.forEach(e=>{ e.data.privesc = ESC_TYPES.has(e.data.type) || (+e.data.weight||1)>=2; });
  const privescTargets=new Set(d.edges.filter(e=>e.data.privesc).map(e=>e.data.target));
  d.nodes.forEach(n=>{ n.data.onpath=pathNodes.has(n.data.id); n.data.foothold=(n.data.id===FOOTHOLD); n.data.klass=nodeClass(n.data.node_type);
    n.data.crown = CROWN_TYPES.has(n.data.node_type) || (privescTargets.has(n.data.id) && nodeClass(n.data.node_type)==='identity'); });
  const scopeAccts=(SCOPES||[]).map(s=>s.account).filter(Boolean);
  const SCOPE_SET=new Set(scopeAccts.length?scopeAccts
    :d.nodes.map(n=>String(n.data.id||'').split('|')[1]).filter(a=>a && a!=='external' && a!=='public' && !a.includes('.')));
  d.edges.forEach(e=>{ const sa=String(e.data.source||'').split('|')[1]||'', ta=String(e.data.target||'').split('|')[1]||'';
    e.data.cross_scope = !!(sa && ta && sa!==ta && SCOPE_SET.has(sa) && SCOPE_SET.has(ta)); });
  const lc=$('legend-crossscope'); if(lc) lc.style.display=d.edges.some(e=>e.data.cross_scope)?'flex':'none';
  const clusterNodes=buildClusters(d.nodes, CLUSTER_ON);
  const DENSE = d.nodes.length > 45;
  const MULTI_SCOPE = new Set(d.nodes.map(n=>String(n.data.id||'').split('|')[1]).filter(Boolean)).size>1;
  cy=cytoscape({
    container:$('cy'), elements:{nodes:[...clusterNodes,...d.nodes],edges:d.edges}, minZoom:.08, maxZoom:2.5, layout:{name:'preset'},
    style:[
      { selector:'node:parent', style:{
        'shape':'round-rectangle','background-color':'#12151c','background-opacity':.6,
        'border-width':1.6,'border-style':'dashed','border-color':'#6B7686','padding':26,
        'label':'data(label)','text-valign':'top','text-halign':'center','text-margin-y':-2,
        'font-family':'ui-monospace,monospace','font-size':11.5,'font-weight':700,'color':'#E4E8EE',
        'text-background-color':'#0B0D10','text-background-opacity':.9,'text-background-padding':3 } },
      { selector:'node:childless', style:{
        'shape':'hexagon','background-color':'#0e1116',
        'border-width':DENSE?2:2.5, 'border-color':e=>CLASS_COLOR[e.data('klass')],
        'width':DENSE?18:24,'height':DENSE?18:24,
        'label':e=>{ const l=String(e.data('label')||''); const cap=DENSE?16:18; const nm=l.length>cap?l.slice(0,cap)+'…':l;
          const acct=MULTI_SCOPE?(e.data('account')||String(e.data('id')||'').split('|')[1]||''):'';
          if(DENSE) return acct?nm+'\n⟨'+acct+'⟩':nm;
          const meta=[acct?'⟨'+acct+'⟩':'', String(e.data('node_type')||'')].filter(Boolean).join(' ');
          return meta?nm+'\n'+meta:nm; },
        'text-wrap':'wrap','text-valign':'bottom','text-margin-y':DENSE?3:5,'text-halign':'center',
        'font-size':DENSE?7.5:9,'font-family':'ui-monospace,Menlo,monospace','color':'#9AA3AF','line-height':1.3,
        'text-max-width':DENSE?'90px':'120px','min-zoomed-font-size':DENSE?7:0,
        'opacity':e=>highlight && !e.data('onpath') && !e.data('foothold') ? .28 : 1 } },
      { selector:'node[?foothold]', style:{ 'width':32,'height':32,'border-width':3,'border-color':'#F5A623',
        'background-color':'#1a1204','color':'#F5A623','font-weight':'bold',
        'underlay-color':'#F5A623','underlay-opacity':.35,'underlay-padding':11,'underlay-shape':'ellipse' } },
      { selector:'node[?onpath]', style:{ 'underlay-color':e=>CLASS_COLOR[e.data('klass')],'underlay-opacity':.28,'underlay-padding':7,'underlay-shape':'ellipse' } },
      { selector:'edge', style:{
        'curve-style':'bezier','target-arrow-shape':'triangle','arrow-scale':DENSE?.55:.7,
        'width':e=>e.data('on_path')?2.6:((+e.data('weight')||1)>=2?1.6:1),
        'line-color':e=>edgeColor(e), 'target-arrow-color':e=>edgeColor(e),
        'line-style':e=>e.data('nature')==='derived'?'dashed':'solid',
        'label':e=>e.data('on_path')?e.data('type'):'', 'font-size':7,'font-family':'ui-monospace,monospace','color':'#5C636E',
        'text-rotation':'autorotate','text-background-color':'#0B0D10','text-background-opacity':.85,'text-background-padding':2,
        'opacity':e=>highlight && !e.data('on_path')?.14:(e.data('state')==='CONDITIONAL'?.5:.85) } },
      { selector:'edge[?on_path]', style:{ 'line-color':'#F5A623','target-arrow-color':'#F5A623','color':'#F5A623','opacity':1,'z-index':10 } },
      { selector:'edge[?cross_scope]', style:{ 'line-color':'#E040FB','target-arrow-color':'#E040FB','width':3,'opacity':1,'z-index':14 } },
      { selector:'edge.showlabel', style:{ 'label':'data(type)','color':'#C6CDD6','z-index':30,'width':2.4,'opacity':1 } },
      { selector:'edge.label-on', style:{ 'label':'data(type)','color':'#AEB6C0','text-opacity':1,'text-background-opacity':.9,'z-index':12 } },
      { selector:'edge.e-collapsed', style:{ 'display':'none' } },
      { selector:'edge.e-collapsed-rep', style:{ 'width':e=>e.data('on_path')?3:2.4,'label':e=>e.hasClass('fanned')?(e.data('type')||''):('×'+(e.data('collapsed_n')||'')),
        'curve-style':e=>e.hasClass('fanned')?'bezier':'straight',
        'color':'#C6CDD6','font-size':8,'text-opacity':1,'text-background-opacity':.9,'text-background-color':'#0B0D10','z-index':13 } },
      { selector:'node.hover', style:{ 'border-color':'#fff','underlay-color':e=>CLASS_COLOR[e.data('klass')]||'#fff','underlay-opacity':.42,'underlay-padding':9,'underlay-shape':'ellipse' } },
      { selector:'node:selected', style:{ 'border-color':'#F5A623','underlay-color':'#F5A623','underlay-opacity':.45,'underlay-padding':9,'underlay-shape':'ellipse' } },
      { selector:'edge:selected', style:{ 'line-color':'#F5A623','target-arrow-color':'#F5A623','width':3.2 } },
      { selector:'.esc-dim', style:{ 'opacity':.07 } },
      { selector:'edge.esc-flow', style:{
        'line-color':'#FF2D55','target-arrow-color':'#FF2D55','width':3.6,'opacity':1,'z-index':20,
        'line-style':'dashed','line-dash-pattern':[7,5],'target-arrow-shape':'triangle','arrow-scale':1.05,
        'color':'#FF7A96','font-weight':'bold' } },
      { selector:'node.esc-crown', style:{
        'border-color':'#FF2D55','border-width':3.5,'color':'#FF9FB2','font-weight':'bold',
        'underlay-color':'#FF2D55','underlay-opacity':.55,'underlay-padding':14,'underlay-shape':'ellipse','z-index':25 } }
    ]
  });
  hideClusterBtn();
  cy.on('tap','edge',e=>{ hideClusterBtn(); showEdge(e.target.data()); });
  cy.on('tap','node:childless',e=>{ hideClusterBtn(); showNode(e.target.data()); });
  cy.on('tap','node:parent',e=>selectCluster(e.target));
  cy.on('tap',e=>{ if(e.target===cy) hideClusterBtn(); });
  cy.on('mouseover','node:childless',e=>{ e.target.addClass('hover'); tip(e, tipNode(e.target.data())); });
  cy.on('mouseover','edge',e=>{ const t=e.target; t.addClass('showlabel');
    if(t.hasClass('e-collapsed-rep')) expandBundle(t); else if(t.data('bundle_rep')) keepBundle();
    tip(e, tipEdge(t.data())); });
  cy.on('mouseout','node:childless',e=>{ e.target.removeClass('hover'); $('gtip').style.display='none'; });
  cy.on('mouseout','edge',e=>{ const t=e.target; t.removeClass('showlabel');
    if(t.hasClass('e-collapsed-rep')||t.data('bundle_rep')) deferCollapse(); $('gtip').style.display='none'; });
  cy.on('pan zoom drag',()=>{ $('gtip').style.display='none'; if(selectedCluster) positionClusterBtn(); });
  const desc = opts.to ? `Path to ${labelOf(opts.to)}` : '';
  setInspector(d.counts, desc + (d.counts.path_hops?` · ${d.counts.path_hops} hops`:''), d.nodes);
  styleFilter();
  runLayout(cy.elements(':visible'));
  if(ESC_MODE) applyEsc(true);
  if(EDGE_LABELS) cy.edges().addClass('label-on');
  if(COLLAPSE_EDGES) applyCollapse(true);
}
function edgeColor(e){ if(e.data('on_path'))return'#F5A623'; if(e.data('nature')==='derived')return'#A98BFF';
  if((+e.data('weight')||1)>=2)return'#FF2D55'; if(e.data('state')==='CONDITIONAL')return'#E7C14B'; return'#4a5364'; }

/* collapse parallel edges */
function edgeRank(e){ return (e.data('on_path')?1000:0)+(e.data('cross_scope')?500:0)+(+e.data('weight')||1); }
function applyCollapse(on){
  if(!cy)return;
  cy.batch(()=>{
    cy.edges().removeClass('e-collapsed e-collapsed-rep');
    cy.edges().forEach(e=>{ e.removeData('collapsed_ids'); e.removeData('collapsed_n'); e.removeData('bundle_rep'); });
    if(!on)return;
    const groups={};
    cy.edges().forEach(e=>{ const s=e.data('source'), t=e.data('target'); if(!s||!t)return;
      const key=s<t?s+' '+t:t+' '+s; (groups[key]=groups[key]||[]).push(e); });
    Object.values(groups).forEach(g=>{ if(g.length<2)return;
      g.sort((a,b)=>edgeRank(b)-edgeRank(a));
      const rep=g[0], rest=g.slice(1);
      rep.addClass('e-collapsed-rep'); rep.data('collapsed_ids',rest.map(e=>e.id())); rep.data('collapsed_n',g.length);
      rest.forEach(e=>{ e.addClass('e-collapsed'); e.data('bundle_rep',rep.id()); }); });
  });
  styleFilter();
}
function collapseHover(rep,show){ rep[show?'addClass':'removeClass']('fanned');
  (rep.data('collapsed_ids')||[]).forEach(id=>{ const s=cy.getElementById(id);
  s.style('display', show?'element':'none'); s[show?'addClass':'removeClass']('showlabel'); }); }
let bundleTimer=null, activeBundleRep=null;
function expandBundle(rep){ clearTimeout(bundleTimer);
  if(activeBundleRep && activeBundleRep!==rep.id()){ const p=cy.getElementById(activeBundleRep);
    if(p&&p.nonempty()) collapseHover(p,false); }
  activeBundleRep=rep.id(); collapseHover(rep,true); }
function keepBundle(){ clearTimeout(bundleTimer); }
function deferCollapse(){ clearTimeout(bundleTimer); bundleTimer=setTimeout(()=>{
  if(!activeBundleRep||!cy) return; const r=cy.getElementById(activeBundleRep);
  if(r&&r.nonempty()) collapseHover(r,false); activeBundleRep=null; },120); }

/* escalation highway */
let ESC_MODE=false, escAnim=null, escOffset=0;
function applyEsc(on){
  if(!cy)return; cancelAnimationFrame(escAnim); escAnim=null;
  cy.batch(()=>{
    cy.elements().removeClass('esc-dim esc-flow esc-crown');
    if(!on)return;
    const priv=cy.edges().filter(e=>e.data('privesc'));
    const crown=cy.nodes().filter(n=>n.data('crown'));
    const keep=priv.connectedNodes().union(crown).union(priv);
    cy.elements(':childless').difference(keep).addClass('esc-dim');
    priv.addClass('esc-flow'); crown.addClass('esc-crown');
  });
  if(!on)return;
  const step=()=>{ escOffset=(escOffset-0.9); cy.edges('.esc-flow').style('line-dash-offset',escOffset);
    escAnim=requestAnimationFrame(step); };
  escAnim=requestAnimationFrame(step);
}

/* node-class / cluster filter */
function styleFilter(){
  if(!cy) return;
  cy.batch(()=>{
    cy.nodes(':childless').forEach(n=>n.style('display', nodeHidden(n.data())?'none':'element'));
    cy.edges().forEach(e=>{ const s=cy.$id(e.data('source')).data(), t=cy.$id(e.data('target')).data();
      const hidden=(nodeHidden(s)||nodeHidden(t)) || e.hasClass('e-collapsed'); e.style('display', hidden?'none':'element'); });
    cy.nodes(':parent').forEach(p=>p.style('display',
      p.descendants(':childless').filter(c=>!nodeHidden(c.data())).nonempty() ? 'element' : 'none'));
  });
}
function relayoutVisible(){ if(cy) runLayout(cy.elements(':visible')); if(selectedCluster) positionClusterBtn(); }

/* per-cluster spread control */
let selectedCluster=null;
function selectCluster(p){ selectedCluster=p; positionClusterBtn(); }
function hideClusterBtn(){ selectedCluster=null; const b=$('cluster-spread'); if(b) b.style.display='none'; }
function positionClusterBtn(){
  const b=$('cluster-spread'); if(!b) return;
  if(!cy||!selectedCluster||selectedCluster.removed()||selectedCluster.style('display')==='none'){ b.style.display='none'; return; }
  const bb=selectedCluster.renderedBoundingBox();
  b.style.display='flex'; b.style.left=Math.max(4, bb.x2 - b.offsetWidth - 6)+'px'; b.style.top=Math.max(4, bb.y1 + 6)+'px';
}
function spreadCluster(p){
  const kids=p.children();
  if(kids.length<2){ banner('this cluster has only one node'); return; }
  const lay=kids.layout({ name:'grid', avoidOverlap:true, nodeDimensionsIncludeLabels:true,
    avoidOverlapPadding:6, condense:true, fit:false, animate:true, animationDuration:300 });
  lay.one('layoutstop',()=>{ if(cy) cy.animate({center:{eles:p}},{duration:300,complete:positionClusterBtn}); });
  lay.run();
}

/* tooltip */
function tip(e, html){ const t=$('gtip'); t.innerHTML=html; t.style.display='block';
  const p=e.renderedPosition||e.target.renderedMidpoint(); const box=$('cy').getBoundingClientRect();
  t.style.left=Math.min(p.x+14, box.width-290)+'px'; t.style.top=Math.max(8,p.y-10)+'px'; }
function tipNode(d){ return `<div class="t">${esc(d.label)}</div><div class="m">${esc(d.node_type)}</div><div class="cta m">click to inspect</div>`; }
const VIA_HELP={ identity:"granted by the principal's own IAM identity policy", resource:"granted by the target resource's policy", 'identity+resource':"granted by both identity and resource policy" };
function tipEdge(d){ const via=(d.evidence&&d.evidence.via)||d.via||''; return `<div class="t">${esc(d.type)}</div>
  <div class="e">${esc((d.permissions||[]).join(', ')||d.narrative||'')}</div>
  <div class="m">${via?esc(VIA_HELP[via]||via)+' · ':''}conf ${esc(d.confidence==null?'—':d.confidence)}${d.state==='CONDITIONAL'?' · conditional':''}</div>
  <div class="cta m">click to inspect</div>`; }

/* drawer */
function openDrawer(){ $('drawer').classList.add('open'); }
function showEdge(d){
  $('dh-title').textContent=d.type;
  const via=(d.evidence&&d.evidence.via)||d.via||'';
  const chain=(d.derived_chain&&d.derived_chain.length)
    ? `<h4>Derived from</h4><ol class="chain">${d.derived_chain.map(x=>`<li>${esc(x)}</li>`).join('')}</ol>`:'';
  $('dbody').innerHTML=`
    <div>${esc(labelOf(d.source))} <span class="rt">→</span> ${esc(labelOf(d.target))}</div>
    <div style="margin:10px 0">
      <span class="badge2 ${esc(d.nature)}">${esc(d.nature)}</span>
      <span class="badge2 ${d.state==='CONDITIONAL'?'cond':''}">${esc(d.state)}</span>
      ${d.on_path?'<span class="badge2" style="color:var(--amber);border-color:#4a3a1a">on path</span>':''}</div>
    <div class="kv">
      <span class="k">Why</span><span class="v">${esc(d.narrative||'—')}</span>
      <span class="k">Permissions</span><span class="v mono">${esc((d.permissions||[]).join(', ')||'none')}</span>
      ${via?`<span class="k">Granted via</span><span class="v">${esc(String(via).replace('+',' + '))} policy — ${esc(VIA_HELP[via]||'')}</span>`:''}
      <span class="k">Conditions</span><span class="v mono">${esc((d.conditions||[]).join(', ')||'none')}</span>
      <span class="k">Confidence</span><span class="v mono">${esc(d.confidence)}</span>
      <span class="k">Weight</span><span class="v mono">${esc(d.weight)}</span></div>${chain}`;
  openDrawer();
}
function showNode(d){
  $('dh-title').textContent=d.label; openDrawer();
  const nd=nodeDetail(d.id);
  if(!nd||nd.error){ $('dbody').innerHTML=`<div class="muted">${esc((nd&&nd.error)||'no detail')}</div>`; return; }
  const attrs=nd.attributes||{};
  const attrRows=Object.keys(attrs).filter(k=>['alias','key_manager','description','runtime','user_id'].includes(k))
    .map(k=>`<span class="k">${esc(k)}</span><span class="v">${esc(attrs[k])}</span>`).join('');
  const permText=p=>(p&&p.length)?` <span class="rt">(${esc(p.join(', '))})</span>`:'';
  const list=(arr,dir)=>arr.length? arr.map(x=>
      `<div class="rel"><span class="badge2 ${esc(x.nature)}">${esc(x.type)}</span> ${dir==='out'?'→ ':''}<a href="#" data-node="${esc(x.other_id)}">${esc(x.other_label)}</a> <span class="rt">${esc(x.other_type)}</span>${x.state==='CONDITIONAL'?' <span class="badge2 cond">cond</span>':''}${permText(x.permissions)}</div>`).join('')
    : '<div class="muted" style="font-size:12px">none</div>';
  $('dbody').innerHTML=`
    <div class="mono" data-copy="${esc(nd.id)}" title="click to copy" style="font-size:10px;color:var(--fg-3);word-break:break-all;cursor:copy">${esc(nd.id)} ⧉</div>
    <div class="kv" style="margin-top:12px">
      <span class="k">Type</span><span class="v">${esc(nd.node_type)}</span>
      <span class="k">Resource</span><span class="v mono">${esc(nd.resource_type||'—')}</span>
      <span class="k">Account</span><span class="v mono">${esc(nd.account||'—')}</span>${attrRows}</div>
    ${nd.type_help?`<div class="muted" style="font-size:11.5px;line-height:1.5;margin:8px 0">${esc(nd.type_help)}</div>`:''}
    <h4>Policies &amp; memberships (${nd.counts.grants})</h4>${list(nd.grants,'out')}
    <h4>Can do (${nd.counts.outbound})</h4>${list(nd.outbound,'out')}
    <h4>Acted on by (${nd.counts.inbound})</h4>${list(nd.inbound,'in')}
    <div style="display:flex;gap:8px;margin-top:16px">
      <button class="btn" id="set-foot" style="flex:1">Set as foothold</button>
      <button class="btn" id="who-reach" style="flex:1" title="Show every path that reaches this node">Who can reach</button></div>`;
  const b=$('set-foot'); if(b)b.onclick=()=>{ setFoothold(nd.id); $('drawer').classList.remove('open'); };
  const wr=$('who-reach'); if(wr)wr.onclick=()=>{ selEnd=nd.id; $('end-input').value=labelOf(nd.id); $('drawer').classList.remove('open'); banner('paths that reach '+labelOf(nd.id)); runExplore({mode:'reaches',to:nd.id}); };
  $('dbody').querySelectorAll('a[data-node]').forEach(a=>a.onclick=ev=>{ ev.preventDefault();
    const id=a.dataset.node; const el=cy&&cy.$id(id); if(el&&el.nonempty()){cy.animate({center:{eles:el},zoom:1.2},{duration:300});el.select();}
    showNode({id,label:a.textContent}); });
}
function setFoothold(id){ FOOTHOLD=id; $('fh-input').value=labelOf(id); if(tab==='exposures') loadExposures(); else runView(); }

/* typeahead */
function typeahead(input,list,onPick){
  let items=[],active=-1;
  const close=()=>{ list.style.display='none'; active=-1; };
  const hi=()=>[...list.children].forEach((el,i)=>el.classList.toggle('active',i===active));
  const pick=n=>{ input.value=n.label; close(); onPick(n); };
  input.addEventListener('input',()=>{
    const term=input.value.toLowerCase().trim(); if(!term){close();return;}
    items=ALLNODES.map(n=>{ const hay=(n.label+' '+(n.kind||'')+' '+n.id).toLowerCase(); if(!hay.includes(term))return null;
      const l=n.label.toLowerCase(); return {n,s:l.startsWith(term)?0:l.includes(term)?1:2}; })
      .filter(Boolean).sort((a,b)=>a.s-b.s).slice(0,30).map(x=>x.n);
    if(!items.length){close();return;}
    list.innerHTML=items.map((n,i)=>`<div class="ta-item${i===0?' active':''}" data-i="${i}"><div class="l">${esc(n.label)}</div><div class="k">${esc(n.kind||n.node_type)}</div></div>`).join('');
    active=0; list.style.display='block';
    [...list.children].forEach(el=>el.onmousedown=e=>{e.preventDefault();pick(items[+el.dataset.i]);});
  });
  input.addEventListener('keydown',e=>{ if(list.style.display==='none')return;
    if(e.key==='ArrowDown'){active=Math.min(active+1,items.length-1);hi();e.preventDefault();}
    else if(e.key==='ArrowUp'){active=Math.max(active-1,0);hi();e.preventDefault();}
    else if(e.key==='Enter'){if(items[active])pick(items[active]);e.preventDefault();}
    else if(e.key==='Escape')close(); });
  input.addEventListener('blur',()=>setTimeout(close,150));
}

/* ---------- export + report ---------- */
function downloadBlob(text, mime, fname){ const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([text],{type:mime})); a.download=fname;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href),1000); }
function downloadExport(what,fmt){ if(!ENG)return; const r=exportFindings(what,fmt,FOOTHOLD); downloadBlob(r.text,r.mime,r.fname); }
function exportGraphPNG(){ if(!cy){ banner('draw a graph first'); return; }
  const png=cy.png({full:true,scale:2,bg:'#0B0D10'});
  const a=document.createElement('a'); a.href=png; a.download=`${ENG.enid}-graph.png`; document.body.appendChild(a); a.click(); a.remove(); }

function sevClass(s){ return 'sev-'+(s||'low'); }
function buildReportHTML(){
  const foothold=FOOTHOLD||footholdNode(ENG); const nm=NODE_MAP;
  const exp=exposuresList(foothold).exposures;
  const leaks=exp.filter(x=>x.kind==='credential').map(x=>{ const lv=getLeakValue((x.evidence||{}).value_ref||'');
    return Object.assign({}, x, {value:lv.value, decoded:lv.decoded}); });
  const pub=exp.filter(x=>['public','internet','cross_account'].includes(x.kind));
  const ctx={ custody:custody(), generated_at:new Date().toISOString().slice(0,16).replace('T',' ')+' UTC',
    foothold_label: nm.has(foothold)?shorten(foothold,nm):foothold,
    paths:reportPaths(foothold), leaks, public:pub, footholds:rankFootholds(10) };
  const c=ctx.custody;
  const pill=(t,cls)=>`<span class="pill ${cls||''}">${esc(t)}</span>`;
  const pathsHTML = ctx.paths.length ? ctx.paths.map((p,i)=>`
    <div class="path"><h3>${i+1}. → ${esc(p.objective)} ${pill(p.objective_type)}
      ${p.state==='CONDITIONAL'?pill('conditional','cond'):''} ${pill(p.hops+' hop'+(p.hops===1?'':'s'))}</h3>
      ${p.steps.map(s=>`<div class="step"><span class="mono">${esc(s.source)}</span>
        <span class="arrow"> —${esc(s.edge)}→ </span><span class="mono">${esc(s.target)}</span>
        ${s.permissions?pill(s.permissions):''} ${s.state==='CONDITIONAL'?pill('cond','cond'):''}</div>`).join('')}
    </div>`).join('') : '<p class="empty">No paths from the foothold to a high-value objective.</p>';
  const leaksHTML = ctx.leaks.length ? ctx.leaks.map(x=>`
    <div class="leak"><div class="leak-hd"><span class="sev ${sevClass(x.severity)}">${esc(x.severity)}</span>
      <span class="res">${esc(x.label)}</span>${x.decoded?'<span class="decoded">base64-decoded</span>':''}
      <span class="loc">${esc((x.evidence&&x.evidence.location)||x.detail)}</span></div>
      ${x.value?`<pre class="leak-val">${esc(x.value)}</pre>`:'<pre class="leak-val"><span class="empty">not captured (re-scan to reveal)</span></pre>'}</div>`).join('')
    : '<p class="empty">No confirmed leaks.</p>';
  const footHTML = ctx.footholds.length ? `<table><tr><th>Identity</th><th>Type</th><th>Reaches</th><th>Crown jewels</th></tr>
    ${ctx.footholds.map(f=>`<tr><td>${esc(f.label)}</td><td>${esc(f.node_type)}</td><td>${f.reaches}</td><td>${f.crown_jewels}</td></tr>`).join('')}</table>`
    : '<p class="empty">No identities with reachable objectives.</p>';
  const pubHTML = ctx.public.length ? `<table><tr><th>Sev</th><th>Resource</th><th>Finding</th></tr>
    ${ctx.public.map(x=>`<tr><td class="sev ${sevClass(x.severity)}">${esc(x.severity)}</td><td>${esc(x.label)}</td><td>${esc(x.detail)}</td></tr>`).join('')}</table>`
    : '<p class="empty">No public exposures.</p>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Blaze report — ${esc(c.enid)}</title>
<style>
:root{--ink:#14181f;--muted:#5c6572;--line:#d9dee5;--crit:#c0392b;--high:#d35400;--med:#8e44ad;--ok:#1e824c;}
*{box-sizing:border-box;} body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);max-width:900px;margin:0 auto;padding:32px 40px 80px;line-height:1.5;background:#fff;}
h1{font-size:22px;margin:0 0 2px;} h2{font-size:15px;margin:28px 0 8px;border-bottom:2px solid var(--ink);padding-bottom:4px;} h3{font-size:13px;margin:16px 0 4px;}
.sub{color:var(--muted);font-size:12px;margin:0 0 18px;} table{width:100%;border-collapse:collapse;font-size:12px;margin:8px 0 4px;}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;} th{background:#f4f6f8;font-weight:600;}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;}
.custody{display:grid;grid-template-columns:repeat(3,1fr);gap:6px 20px;font-size:12px;background:#f7f9fb;border:1px solid var(--line);border-radius:6px;padding:14px 18px;}
.custody b{color:var(--muted);font-weight:600;display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;}
.sev{font-weight:700;text-transform:uppercase;font-size:10px;} .sev-critical{color:var(--crit)} .sev-high{color:var(--high)} .sev-medium{color:var(--med)} .sev-low{color:var(--muted)}
.pill{display:inline-block;font-size:10px;padding:1px 6px;border-radius:99px;border:1px solid var(--line);color:var(--muted);} .pill.cond{color:var(--high);border-color:var(--high);}
.path{margin:6px 0 14px;padding:10px 12px;border:1px solid var(--line);border-radius:6px;page-break-inside:avoid;} .step{font-size:12px;margin:2px 0;} .step .arrow{color:var(--crit);font-weight:700;}
.kpis{display:flex;gap:26px;margin:10px 0;} .kpi .n{font-size:24px;font-weight:700;} .kpi .l{font-size:11px;color:var(--muted);}
.toolbar{position:sticky;top:0;background:#fff;padding:8px 0;border-bottom:1px solid var(--line);margin-bottom:14px;}
.btn{font:inherit;font-size:12px;padding:6px 14px;border:1px solid var(--ink);background:var(--ink);color:#fff;border-radius:5px;cursor:pointer;}
.empty{color:var(--muted);font-size:12px;font-style:italic;}
.leak{margin:8px 0 14px;border:1px solid var(--line);border-radius:6px;overflow:hidden;page-break-inside:avoid;}
.leak-hd{display:flex;align-items:baseline;flex-wrap:wrap;gap:8px;padding:8px 12px;background:#f7f9fb;border-bottom:1px solid var(--line);}
.leak-hd .res{font-weight:600;font-size:13px;} .leak-hd .loc{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted);word-break:break-all;}
.leak-hd .decoded{font-family:ui-monospace,monospace;font-size:9px;text-transform:uppercase;letter-spacing:.04em;color:#0b6b7a;border:1px solid #9fd6df;background:#eaf7fa;border-radius:4px;padding:1px 5px;}
.leak-val{margin:0;padding:10px 12px;font-family:ui-monospace,Menlo,monospace;font-size:11px;line-height:1.5;white-space:pre-wrap;word-break:break-all;background:#fff;color:var(--ink);}
@media print{.toolbar{display:none} body{padding:0 8px} h2{margin-top:20px}}
</style></head><body>
<div class="toolbar"><button class="btn" onclick="window.print()">🖶 Print / Save as PDF</button></div>
<h1>Attack-path assessment — ${esc(c.name||c.enid)}</h1>
<p class="sub">Engagement ${esc(c.enid)} · ${esc((c.provider||'').toUpperCase())} · generated ${esc(ctx.generated_at)}</p>
<h2>Chain of custody</h2>
<div class="custody">
  <div><b>Account</b>${esc(c.account||'—')}</div>
  <div><b>Collected as</b><span class="mono">${esc(c.caller||'—')}</span></div>
  <div><b>Collected at</b>${esc(c.collected_at||'—')}</div>
  <div><b>Collector</b>${esc(c.collector_version)}</div>
  <div><b>Engine</b>${esc(c.engine_version)}</div>
  <div><b>RAGE</b>${esc(c.rage_version||'—')}${c.rage_version && c.rage_version!==SUPPORTED_RAGE?` <span style="color:#f7c948">⚠ built for RAGE ${esc(c.rage_version)}; viewer supports ${SUPPORTED_RAGE}</span>`:''}</div>
  <div><b>Default foothold</b>${esc(ctx.foothold_label)}</div>
</div>
<h2>Summary</h2>
<div class="kpis">
  <div class="kpi"><div class="n">${esc((c.counts&&c.counts.nodes)||ENG.nodes.length)}</div><div class="l">Nodes</div></div>
  <div class="kpi"><div class="n">${esc((c.counts&&c.counts.edges)||ENG.edges.length)}</div><div class="l">Attack edges</div></div>
  <div class="kpi"><div class="n">${ctx.paths.length}</div><div class="l">Paths to crown jewels</div></div>
  <div class="kpi"><div class="n">${ctx.leaks.length}</div><div class="l">Confirmed leaks</div></div>
  <div class="kpi"><div class="n">${ctx.public.length}</div><div class="l">Public exposures</div></div>
</div>
<h2>Most dangerous footholds (by blast radius)</h2>${footHTML}
<h2>Attack paths from ${esc(ctx.foothold_label)}</h2>${pathsHTML}
<h2>Confirmed leaks (captured values)</h2>${leaksHTML}
<h2>Public / internet-facing exposures</h2>${pubHTML}
<p class="sub" style="margin-top:30px">Captured values are the real data read from each resource during collection — handle this report as sensitive. Generated by Thunderstorm / Blaze Lite.</p>
</body></html>`;
}
function openReport(){ if(!ENG){ banner('load an engagement first'); return; }
  const w=window.open('', '_blank'); if(!w){ toast('popup blocked — allow popups to open the report', true); return; }
  w.document.open(); w.document.write(buildReportHTML()); w.document.close(); }

/* ============================================================================
   EXPOSURES TAB  (ported from Blaze engagements.html — client-side data +
   localStorage triage instead of server /exposures, /triage, /leak)
   ============================================================================ */
let EXPO=[], EXPO_FILTER={sev:'',kind:'',reach:''}, EXPO_SORT='sev', TRIAGE={};
const SEV_COLOR={critical:'#ff5a5a',high:'#f5a623',medium:'#7c8cff',low:'#6b7280'};
const TRI_LABEL={'':'triage…','confirmed':'✓ confirmed','false-positive':'✕ false-pos','reviewed':'● reviewed'};
const kindLabel={ credential:'confirmed leak', public:'public', internet:'internet-facing', cross_account:'cross-account' };

// triage persists per-engagement in localStorage (the offline analog of the server store).
function triageKey(){ return 'blaze-lite-triage:'+(ENG?ENG.enid:''); }
function loadTriage(){ try{ return JSON.parse(localStorage.getItem(triageKey())||'{}')||{}; }catch(e){ return {}; } }
function saveTriage(key,status){ const t=loadTriage(); if(status) t[key]={status}; else delete t[key];
  try{ localStorage.setItem(triageKey(), JSON.stringify(t)); }catch(e){} TRIAGE=t; }

function loadExposures(){
  if(!ENG) return;
  const d=exposuresList(FOOTHOLD);
  EXPO=d.exposures||[]; TRIAGE=loadTriage();
  renderExposures(d);
}
function findingKey(x){ return x.kind+':'+((x.evidence&&x.evidence.value_ref) || x.node_id || x.label)+':'+(x.detail||''); }
function renderExposures(meta){
  const F=EXPO_FILTER;
  let rows=EXPO.filter(x=>(!F.sev||x.severity===F.sev)&&(!F.kind||x.kind===F.kind)&&(!F.reach||(F.reach==='y'?x.reachable:!x.reachable)));
  rows.sort((a,b)=> EXPO_SORT==='sev'? (SEV_RANK[a.severity]??9)-(SEV_RANK[b.severity]??9)||a.label.localeCompare(b.label)
                   : EXPO_SORT==='kind'? a.kind.localeCompare(b.kind) : a.label.localeCompare(b.label));
  const opt=(v,cur)=>`<option value="${v}" ${v===cur?'selected':''}>${v||'all'}</option>`;
  const body=rows.map(x=>{ const k=findingKey(x); const t=TRIAGE[k]||{}; const st=t.status||'';
    const ev=x.evidence||{};
    return `<tr data-k="${esc(k)}" style="box-shadow:inset 4px 0 0 ${SEV_COLOR[x.severity]||'#555'}" title="severity: ${esc(x.severity||'unknown')}">
      <td>${esc(x.label)} <span class="rt mono" style="color:var(--fg-3)">${esc(x.node_type)}</span>
        ${(ev.location||ev.decoded)?`<div class="mono" style="font-size:10px;color:var(--fg-3);margin-top:3px">${ev.decoded?'<span class="decoded-badge" title="Stored base64-encoded on the resource; shown decoded">base64-decoded</span>':''}${esc(ev.location||'')}</div>`:''}
        ${x.kind==='credential'?(ev.has_value
            ?`<div class="expo-val mono" data-ref="${esc(ev.value_ref)}" style="font-size:10.5px;color:var(--lime);margin-top:3px;word-break:break-all"><span class="ev-prev">${esc(ev.preview||'')}</span> <span class="ev-reveal" style="color:var(--cyan);cursor:pointer;border:1px solid var(--line-2);border-radius:3px;padding:0 4px">reveal ⤢</span></div>`
            :`<div class="mono" style="font-size:10px;color:var(--fg-3);margin-top:2px">${esc(ev.preview||'value not captured')}</div>`):''}</td>
      <td><span class="tag">${esc(kindLabel[x.kind]||x.kind)}</span></td>
      <td style="white-space:nowrap">
        <select class="tri t-${st||'none'}" data-k="${esc(k)}" title="triage status">
          ${['','confirmed','false-positive','reviewed'].map(s=>`<option value="${s}" ${s===st?'selected':''}>${TRI_LABEL[s]}</option>`).join('')}
        </select>
        ${x.reachable&&x.node_id?`<button class="btn" data-to="${esc(x.node_id)}" style="margin-left:6px">show path</button>`:''}</td></tr>`;}).join('');
  const anyVals=rows.some(x=>x.evidence&&x.evidence.has_value);
  $('view-exposures').innerHTML=`
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px">
      <span class="bracket">[ <b>SENSITIVE EXPOSURES</b> ]</span>
      <span style="flex:1"></span>
      ${anyVals?`<span class="chip" id="expo-revealall">⤢ reveal all</span>`:''}
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;font-size:12px">
      <span class="muted">${rows.length} of ${EXPO.length} · ${meta?meta.reachable_count||0:0} reachable from ${esc(FOOTHOLD?labelOf(FOOTHOLD):'—')}</span>
      <span style="flex:1"></span>
      <label class="muted">sev <select id="fx-sev" class="fx">${['','critical','high','medium','low'].map(v=>opt(v,F.sev)).join('')}</select></label>
      <label class="muted">kind <select id="fx-kind" class="fx">${['','credential','public','internet','cross_account'].map(v=>opt(v,F.kind)).join('')}</select></label>
      <label class="muted">reach <select id="fx-reach" class="fx"><option value="">all</option><option value="y" ${F.reach==='y'?'selected':''}>reachable</option><option value="n" ${F.reach==='n'?'selected':''}>not</option></select></label>
      <button class="chip" id="fx-export">⬇ CSV</button>
    </div>
    <div class="card" style="overflow:hidden"><table class="eng" style="width:100%;border-collapse:collapse;font-size:12.5px">
      <thead><tr>
        ${[['resource','resource'],['kind','kind'],['triage','']].map(([h,s])=>`<th class="colh" data-sort="${s}" style="text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--fg-3);padding:9px 12px;border-bottom:1px solid var(--line);cursor:${s?'pointer':'default'}">${h}${s?' ⇅':''}</th>`).join('')}
      </tr></thead>
      <tbody>${body||'<tr><td colspan=3 class="muted" style="padding:16px">no exposures match the filter</td></tr>'}</tbody></table></div>`;
  document.querySelectorAll('.fx').forEach(s=>s.style.cssText='color-scheme:dark;background:#0e1116;color:var(--fg);border:1px solid var(--line-2);border-radius:5px;padding:4px 6px;margin-left:4px;font-family:var(--mono)');
  $('fx-sev').onchange=e=>{EXPO_FILTER.sev=e.target.value;renderExposures(meta);};
  $('fx-kind').onchange=e=>{EXPO_FILTER.kind=e.target.value;renderExposures(meta);};
  $('fx-reach').onchange=e=>{EXPO_FILTER.reach=e.target.value;renderExposures(meta);};
  $('fx-export').onclick=()=>downloadExport('exposures','csv');
  const revAll=$('expo-revealall');
  if(revAll) revAll.onclick=()=>{
    if(revAll.dataset.on==='1'){ renderExposures(meta); return; }
    $('view-exposures').querySelectorAll('.expo-val .ev-reveal').forEach(rv=>rv.click());
    revAll.textContent='⤡ hide all'; revAll.dataset.on='1';
  };
  document.querySelectorAll('.colh').forEach(th=>{ if(th.dataset.sort) th.onclick=()=>{ EXPO_SORT=th.dataset.sort==='resource'?'label':th.dataset.sort; renderExposures(meta); }; });
  $('view-exposures').querySelectorAll('button[data-to]').forEach(b=>b.onclick=()=>{ setTab('paths');
    if(selEnd=b.dataset.to)$('end-input').value=labelOf(b.dataset.to); runExplore({mode:'reaches',to:b.dataset.to}); });
  $('view-exposures').querySelectorAll('select.tri').forEach(s=>s.onchange=()=>{
    saveTriage(s.dataset.k, s.value); s.className='tri t-'+(s.value||'none'); toast('triage saved'); });
  $('view-exposures').querySelectorAll('.expo-val .ev-reveal').forEach(rv=>rv.onclick=()=>{
    const el=rv.closest('.expo-val'), ref=el.dataset.ref;
    const d=getLeakValue(ref);
    if(!d.has_value){ el.innerHTML='<span style="color:var(--fg-3)">value not captured</span>'; return; }
    el.innerHTML=`<div style="display:flex;justify-content:space-between;color:var(--fg-3);font-size:9.5px;margin-bottom:2px"><span>captured value · ${d.length} b</span><span><span class="ev-copy" style="cursor:pointer;color:var(--cyan)">copy</span> · <span class="ev-hide" style="cursor:pointer;color:var(--fg-3)">hide</span></span></div><pre style="margin:0;max-height:26vh;overflow:auto;white-space:pre-wrap;word-break:break-all;background:#0b0d10;border:1px solid var(--line-2);border-radius:5px;padding:5px 7px;color:var(--lime);font-size:10.5px">${esc(d.value)}</pre>`;
    el.querySelector('.ev-copy').onclick=()=>{ navigator.clipboard.writeText(d.value); toast('captured value copied'); };
    el.querySelector('.ev-hide').onclick=()=>renderExposures(meta);
  });
}
function setTab(t){ tab=t;
  document.querySelectorAll('.tabs .chip').forEach(el=>el.classList.toggle('active',el.dataset.tab===t));
  const paths=t==='paths';
  $('view-graph').style.display=paths?'block':'none';
  $('view-exposures').style.display=paths?'none':'block';
  if(paths){ if(!cy)runView(); } else loadExposures();
}

/* ============================================================================
   LOAD FLOW + WIRING
   ============================================================================ */
async function loadFromBytes(fileName, u8){
  const buckets=emptyBuckets();
  const lower=fileName.toLowerCase();
  try{
    if(lower.endsWith('.zip')){
      const files=await parseZip(u8);
      const rageName=Object.keys(files).find(n=>n.endsWith('.rage.ndjson'));
      if(rageName){ parseNdjson(files[rageName], buckets); }
      else {
        if(files['graph/nodes.ndjson']) parseNdjson(files['graph/nodes.ndjson'], buckets);
        if(files['graph/edges.ndjson']) parseNdjson(files['graph/edges.ndjson'], buckets);
        if(files['graph/paths.ndjson']) parseNdjson(files['graph/paths.ndjson'], buckets);
        if(files['exposure/hits.ndjson']) parseNdjson(files['exposure/hits.ndjson'], buckets);
        if(files['exposure/surfaces.ndjson']) parseNdjson(files['exposure/surfaces.ndjson'], buckets);
        if(files['engagement.json']){ try{ buckets.manifest=JSON.parse(files['engagement.json']); }catch(e){} }
      }
      if(!buckets.node.length && !buckets.edge.length)
        throw new Error('zip has no graph (expected graph.rage.ndjson or graph/nodes.ndjson)');
    } else {
      parseNdjson(new TextDecoder('utf-8').decode(u8), buckets);
      if(!buckets.node.length && !buckets.edge.length) throw new Error('no node/edge records found in file');
    }
  }catch(err){ showEmpty('Could not load file', err.message||String(err)); toast('load failed', true); return; }
  buildEngagement(fileName, buckets);
  onEngagementLoaded();
}
function loadFromText(fileName, text){ return loadFromBytes(fileName, new TextEncoder().encode(text)); }

function onEngagementLoaded(){
  SCOPES = ENG.scopes || [];
  ALLNODES = nodeList(ENG);
  FOOTHOLD = collectFoothold = footholdNode(ENG);
  selEnd=null; $('end-input').value=''; $('fh-input').value = FOOTHOLD?labelOf(FOOTHOLD):'';
  $('lensbar').style.display='flex';
  $('load-name').textContent = ENG.enid;
  if(ENG.provider){ $('pill-provider').style.display=''; $('sp-provider').textContent=ENG.provider.toUpperCase(); }
  $('strip-ctx').innerHTML=`[ <b>${esc(ENG.enid)}</b>${ENG.provider?` · <span class="mono">${esc(ENG.provider)}</span>`:''} · ${ALLNODES.length} nodes · ${ENG.edges.length} edges ]`;
  VIEW_MODE='auto'; tab='paths';
  document.querySelectorAll('.tabs .chip').forEach(el=>el.classList.toggle('active', el.dataset.tab==='paths'));
  $('view-graph').style.display='block'; $('view-exposures').style.display='none';
  runView();
}

/* file/drag input */
function handleFile(file){ if(!file) return; const reader=new FileReader();
  reader.onload=()=>loadFromBytes(file.name, new Uint8Array(reader.result));
  reader.readAsArrayBuffer(file); }

function wire(){
  typeahead($('fh-input'),$('fh-list'),n=>setFoothold(n.id));
  typeahead($('end-input'),$('end-list'),n=>{ selEnd=n?n.id:null; });
  $('fh-collect').onclick=()=>{ if(collectFoothold)setFoothold(collectFoothold); };
  document.querySelectorAll('.tabs .chip').forEach(el=>el.onclick=()=>{ if(ENG) setTab(el.dataset.tab); });
  $('go-path').onclick=()=>{ if(!FOOTHOLD)return banner('pick a foothold'); if(!selEnd)return banner('pick a destination'); setTab('paths'); runExplore({mode:'path',from:FOOTHOLD,to:selEnd}); };
  $('cond').classList.add('active');
  $('cluster').classList.add('active');
  $('cluster').onclick=()=>{ $('cluster').classList.toggle('active'); CLUSTER_ON=$('cluster').classList.contains('active');
    if(cy&&lastData) render(lastData,lastOpts); };
  $('esc').onclick=()=>{ $('esc').classList.toggle('active'); ESC_MODE=$('esc').classList.contains('active'); applyEsc(ESC_MODE); };
  const rerun=()=>{ if(lastQueryOpts) runExplore(lastQueryOpts); else runView(); };
  ['cond','struct'].forEach(id=>$(id).onclick=()=>{ $(id).classList.toggle('active'); rerun(); });
  $('edgelabels').onclick=()=>{ $('edgelabels').classList.toggle('active'); EDGE_LABELS=$('edgelabels').classList.contains('active');
    if(cy) cy.edges()[EDGE_LABELS?'addClass':'removeClass']('label-on'); };
  $('collapse').onclick=()=>{ $('collapse').classList.toggle('active'); COLLAPSE_EDGES=$('collapse').classList.contains('active'); applyCollapse(COLLAPSE_EDGES); };
  $('cluster-spread').onclick=()=>{ if(selectedCluster) spreadCluster(selectedCluster); };
  $('hops').addEventListener('change',rerun);
  $('display-btn').onclick=e=>{ e.stopPropagation(); const p=$('display-pop'), open=!p.classList.contains('open');
    p.classList.toggle('open',open);
    if(open){ p.style.left='0'; requestAnimationFrame(()=>{ const M=8, r=p.getBoundingClientRect(); let shift=0;
      if(r.right>window.innerWidth-M) shift=(window.innerWidth-M)-r.right; if(r.left+shift<M) shift=M-r.left; p.style.left=shift+'px'; }); } };
  document.addEventListener('click',e=>{ if(!e.target.closest('.lens-menu')) $('display-pop').classList.remove('open'); });
  const markDirty=()=>{ const on=id=>$(id).classList.contains('active');
    $('display-btn').classList.toggle('dirty', on('esc')||!on('cond')||!on('cluster')||on('struct')||!on('edgelabels')||on('collapse')||$('hops').value!=='6'); };
  ['cluster','esc','cond','struct','edgelabels','collapse'].forEach(id=>$(id).addEventListener('click',markDirty));
  $('hops').addEventListener('change',markDirty);
  document.querySelectorAll('#inspector .nclass').forEach(el=>el.onclick=()=>{ const k=el.dataset.klass;
    if(hiddenClasses.has(k)){ hiddenClasses.delete(k); el.classList.remove('off'); } else{ hiddenClasses.add(k); el.classList.add('off'); }
    styleFilter(); relayoutVisible(); });
  document.querySelectorAll('.chip.vm').forEach(c=>c.onclick=()=>{
    document.querySelectorAll('.chip.vm').forEach(x=>x.classList.remove('active')); c.classList.add('active');
    VIEW_MODE=c.dataset.vm; runView(); });

  // drawer close
  $('dclose').onclick=()=>$('drawer').classList.remove('open');
  document.addEventListener('keydown',e=>{ if(e.key==='Escape')$('drawer').classList.remove('open'); });
  document.addEventListener('click',e=>{ const c=e.target.closest('[data-copy]'); if(c){ (navigator.clipboard?navigator.clipboard.writeText(c.dataset.copy):Promise.reject()).then(()=>toast('copied to clipboard')).catch(()=>toast('copy failed',true)); } });

  // export menu
  $('export-btn').onclick=e=>{ e.stopPropagation();
    let m=$('export-menu'); if(m){ m.remove(); return; }
    m=document.createElement('div'); m.id='export-menu';
    m.style.cssText='position:absolute;z-index:60;background:#12151b;border:1px solid #2a2f38;border-radius:8px;padding:8px;font-size:12px;box-shadow:0 8px 24px rgba(0,0,0,.5);min-width:200px';
    const b=$('export-btn').getBoundingClientRect(); m.style.left=Math.max(8,b.left-60)+'px'; m.style.top=(b.bottom+6)+'px';
    const item=(t,fn)=>{ const el=document.createElement('div'); el.textContent=t; el.style.cssText='padding:6px 10px;border-radius:5px;cursor:pointer;color:#cfd6df';
      el.onmouseover=()=>el.style.background='rgba(255,255,255,.05)'; el.onmouseout=()=>el.style.background=''; el.onclick=()=>{ fn(); m.remove(); }; return el; };
    [['⬇ Leaks (CSV)',()=>downloadExport('leaks','csv')],['⬇ Leaks (JSON)',()=>downloadExport('leaks','json')],
     ['⬇ Exposures (CSV)',()=>downloadExport('exposures','csv')],['⬇ Attack paths (Markdown)',()=>downloadExport('paths','md')],
     ['⬇ Reachable set (CSV)',()=>downloadExport('reachable','csv')],['🖼 Graph image (PNG)',exportGraphPNG]].forEach(([t,fn])=>m.appendChild(item(t,fn)));
    document.body.appendChild(m); };
  document.addEventListener('click',()=>{ const m=$('export-menu'); if(m)m.remove(); });
  $('report-link').onclick=openReport;

  // file loading
  $('load-btn').onclick=()=>$('file-input').click();
  $('file-input').onchange=e=>{ if(e.target.files[0]) handleFile(e.target.files[0]); e.target.value=''; };
  const dz=$('dropzone'); let dragDepth=0;
  window.addEventListener('dragenter',e=>{ e.preventDefault(); dragDepth++; dz.classList.add('over'); });
  window.addEventListener('dragover',e=>{ e.preventDefault(); });
  window.addEventListener('dragleave',e=>{ e.preventDefault(); if(--dragDepth<=0){ dragDepth=0; dz.classList.remove('over'); } });
  window.addEventListener('drop',e=>{ e.preventDefault(); dragDepth=0; dz.classList.remove('over');
    const f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0]; if(f) handleFile(f); });

  // keyboard shortcuts
  document.addEventListener('keydown',e=>{
    if(/input|select|textarea/i.test(e.target.tagName))return; if(e.metaKey||e.ctrlKey)return;
    if(e.key==='/'){ if(ENG){ $('fh-input').focus(); e.preventDefault(); } }
    else if(e.key==='g'){ if(ENG) setTab('paths'); }
    else if(e.key==='e'){ if(ENG) setTab('exposures'); }
    else if(e.key==='f'){ if(collectFoothold)setFoothold(collectFoothold); }
  });
}

/* auto-load from a `thunderstorm view --in` injection */
async function tryEmbedded(){
  const tag=$('blaze-embedded'); if(!tag) return false;
  const raw=(tag.textContent||'').trim(); if(!raw) return false;
  let payload; try{ payload=JSON.parse(raw); }catch(e){ return false; }
  if(!payload || !payload.b64) return false;
  const bin=atob(payload.b64); const u8=Uint8Array.from(bin, c=>c.charCodeAt(0));
  await loadFromBytes(payload.filename||'engagement.ndjson', u8);
  return true;
}

document.addEventListener('DOMContentLoaded', async ()=>{
  wire();
  try{ await tryEmbedded(); }catch(e){ /* fall through to drag prompt */ }
});
