require('dotenv').config();
const express=require('express');
const cors=require('cors');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {createClient}=require('@libsql/client');
const rateLimit=require('express-rate-limit');
const {randomUUID}=require('crypto');

const required=['TURSO_DATABASE_URL','TURSO_AUTH_TOKEN','JWT_SECRET','ADMIN_USERNAME','ADMIN_PASSWORD'];
for(const k of required){if(!process.env[k])throw new Error(`Missing required environment variable: ${k}`)}
if(process.env.JWT_SECRET.length<32)throw new Error('JWT_SECRET must be at least 32 characters');
const db=createClient({url:process.env.TURSO_DATABASE_URL,authToken:process.env.TURSO_AUTH_TOKEN});
const app=express();
app.disable('x-powered-by');
app.use(cors({origin:process.env.CORS_ORIGIN||'*'}));
app.use(express.json({limit:'5mb'}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:80,standardHeaders:true,legacyHeaders:false}));

const cols='id,name,mobile,email,username,role,status,created_at,custom_link,phone_verified';
const pub=u=>({id:u.id,name:u.name,mobile:u.mobile,email:u.email||'',role:u.role,status:u.status,createdAt:u.created_at,customLink:u.custom_link||'',phoneVerified:!!u.phone_verified});
const sign=u=>jwt.sign({sub:u.id,role:u.role},process.env.JWT_SECRET,{expiresIn:'12h'});

async function auth(req,res,next){
  try{
    const h=req.headers.authorization||'';
    const p=jwt.verify(h.startsWith('Bearer ')?h.slice(7):'',process.env.JWT_SECRET);
    const r=await db.execute({sql:`SELECT ${cols} FROM users WHERE id=?`,args:[p.sub]});
    if(!r.rows[0]||r.rows[0].status==='blocked')return res.status(401).json({error:'Account unavailable'});
    req.user=r.rows[0];next();
  }catch{return res.status(401).json({error:'Please log in again'})}
}
const adminOnly=(req,res,next)=>req.user?.role==='admin'?next():res.status(403).json({error:'Admin access required'});

async function audit(actor,action,target='',details=''){
  try{await db.execute({sql:'INSERT INTO audit_log(id,actor,action,target,details,created_at) VALUES(?,?,?,?,?,?)',args:[randomUUID(),actor,action,String(target).slice(0,200),String(details).slice(0,1000),new Date().toISOString()]})}catch(e){console.error('audit:',e.message)}
}
async function getConfig(keys){
  const r=await db.execute({sql:`SELECT key,value FROM config WHERE key IN (${keys.map(()=>'?').join(',')})`,args:keys});
  return Object.fromEntries(r.rows.map(x=>[x.key,x.value]));
}
async function setConfig(key,value){
  await db.execute({sql:"INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",args:[key,String(value)]});
}
async function bumpUpdate(){
  const c=await getConfig(['update_seq']);
  const n=(Number(c.update_seq)||0)+1;
  await setConfig('update_seq',n);
  return n;
}

// Firebase Cloud Messaging HTTP v1.
let googleAuth=null;
async function getFcmAccessToken(){
  if(!process.env.FIREBASE_SERVICE_ACCOUNT_JSON)throw new Error('Firebase push is not configured');
  if(!googleAuth){
    const {GoogleAuth}=require('google-auth-library');
    let credentials;
    try{credentials=JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)}catch{throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON')}
    googleAuth=new GoogleAuth({credentials,scopes:['https://www.googleapis.com/auth/firebase.messaging']});
  }
  const client=await googleAuth.getClient();
  const t=await client.getAccessToken();
  const token=typeof t==='string'?t:t?.token;
  if(!token)throw new Error('Could not obtain Firebase access token');
  return token;
}
async function sendPushToTokens(tokens,title,body,link='',image=''){
  const unique=[...new Set(tokens.map(String).filter(Boolean))];
  if(!unique.length)return {sent:0,total:0,failed:0,removed:0,status:'no_registered_devices'};
  if(!process.env.FIREBASE_PROJECT_ID)return {sent:0,total:unique.length,failed:unique.length,removed:0,status:'firebase_not_configured',error:'FIREBASE_PROJECT_ID is not configured'};
  let access;
  try{access=await getFcmAccessToken()}catch(e){console.error('FCM auth:',e.message);return {sent:0,total:unique.length,failed:unique.length,removed:0,status:'firebase_auth_failed',error:e.message}}
  let sent=0,failed=0,removed=0;
  for(const token of unique){
    try{
      const notification={title:title||'Live Portal',body:body||''};
      if(image)notification.image=String(image);
      const message={token,notification,data:{link:String(link||''),image:String(image||'')},android:{priority:'HIGH',notification:{channel_id:'live_portal_updates',sound:'default',click_action:'FLUTTER_NOTIFICATION_CLICK'}}};
      const r=await fetch(`https://fcm.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT_ID}/messages:send`,{
        method:'POST',headers:{Authorization:`Bearer ${access}`,'content-type':'application/json'},body:JSON.stringify({message})
      });
      if(r.ok){sent++;continue}
      failed++;
      const text=await r.text();
      console.error('FCM send failed:',r.status,text.slice(0,500));
      if(r.status===404||r.status===400){
        try{await db.execute({sql:'DELETE FROM device_tokens WHERE token=?',args:[token]});removed++}catch{}
      }
    }catch(e){failed++;console.error('FCM token error:',e.message)}
  }
  return {sent,total:unique.length,failed,removed,status:failed===0?'sent':sent>0?'partial':'failed'};
}

app.get('/health',async(_q,s)=>{
  try{
    await db.execute('SELECT 1');
    s.json({ok:true,database:'turso',push:!!process.env.FIREBASE_PROJECT_ID});
  }catch(e){s.status(503).json({ok:false,error:'Database unavailable'})}
});

app.get('/api/config',async(_q,s)=>{
  try{
    const c=await getConfig(['broadcast','broadcast_title','broadcast_link','broadcast_image','broadcast_last_status','broadcast_last_sent','broadcast_last_total','broadcast_last_failed','broadcast_last_at','maintenance','alert_enabled','alert_title','alert_body','alert_link','developer_details','languages','update_seq']);
    let developer={name:'Sandeep Kumar',course:'BGS Second Semester',skills:['Website Developer','App Developer','Android Developer','Full-Stack Developer','Frontend Developer','Backend Developer','API Developer','Database Developer','Bot Developer','Automation Developer','UI/UX Developer','3D Website Developer','Cloud Deployment','Server Management','JavaScript Developer','Node.js Developer'],friends:['Niteesh','Pintu','Chhotu','Anil']};
    try{if(c.developer_details)developer=JSON.parse(c.developer_details)}catch{}
    let languages=['Hindi','English','Bihari'];
    try{if(c.languages)languages=JSON.parse(c.languages)}catch{}
    const broadcastImageUrl=c.broadcast_image?`${_q.protocol}://${_q.get('host')}/api/broadcast-image?v=${Number(c.broadcast_update_seq||c.update_seq||0)}`:'';
    s.json({broadcast:c.broadcast||'',broadcastTitle:c.broadcast_title||'Live Portal',broadcastLink:c.broadcast_link||'',broadcastImage:broadcastImageUrl,broadcastStatus:{status:c.broadcast_last_status||'',sent:Number(c.broadcast_last_sent)||0,total:Number(c.broadcast_last_total)||0,failed:Number(c.broadcast_last_failed)||0,at:c.broadcast_last_at||''},maintenance:c.maintenance==='true',alert:{enabled:c.alert_enabled==='true',title:c.alert_title||'',body:c.alert_body||'',link:c.alert_link||''},developer,languages,updateSeq:Number(c.update_seq)||0});
  }catch(e){console.error(e);s.status(500).json({error:'Could not load config'})}
});

// Public lightweight update endpoint used by the app's foreground/fallback polling.
app.get('/api/updates',async(req,res)=>{
  try{
    const c=await getConfig(['broadcast','broadcast_title','broadcast_link','broadcast_image','alert_enabled','alert_title','alert_body','alert_link','update_seq']);
    const seq=Number(c.update_seq)||0;
    const since=Number(req.query?.since)||0;
    const imageUrl=c.broadcast_image?`${req.protocol}://${req.get('host')}/api/broadcast-image?v=${seq}`:'';
    res.json({updateSeq:seq,changed:seq>since,broadcast:c.broadcast||'',broadcastTitle:c.broadcast_title||'Live Portal',broadcastLink:c.broadcast_link||'',broadcastImage:imageUrl,alert:{enabled:c.alert_enabled==='true',title:c.alert_title||'',body:c.alert_body||'',link:c.alert_link||''}});
  }catch(e){res.status(500).json({error:'Could not load updates'})}
});

app.post('/api/auth/register',async(req,res)=>{
  try{
    const {name,mobile,email='',password}=req.body||{};
    const cleanName=String(name||'').trim(),cleanMobile=String(mobile||'').trim(),cleanEmail=String(email||'').trim().toLowerCase();
    if(!cleanName||!/^\+?[0-9]{10,15}$/.test(cleanMobile)||typeof password!=='string'||password.length<10||password.length>128)return res.status(400).json({error:'Enter valid name, mobile number and a 10–128 character password'});
    if(cleanEmail.length>254)return res.status(400).json({error:'Invalid email'});
    const ex=await db.execute({sql:'SELECT id FROM users WHERE mobile=?',args:[cleanMobile]});
    if(ex.rows.length)return res.status(409).json({error:'Mobile number already registered'});
    const id=randomUUID(),hash=await bcrypt.hash(password,12),now=new Date().toISOString(),username='u_'+cleanMobile.replace(/\D/g,'');
    await db.execute({sql:'INSERT INTO users(id,name,mobile,email,username,password_hash,role,status,created_at,custom_link,phone_verified) VALUES(?,?,?,?,?,?,?,?,?,?,1)',args:[id,cleanName,cleanMobile,cleanEmail,username,hash,'user','pending',now,'',1]});
    await audit('system','user_registered',id,`${cleanName}, mobile ${cleanMobile}`);
    res.status(201).json({message:'Registration submitted; wait for admin approval'});
  }catch(e){console.error(e);res.status(500).json({error:'Registration failed'})}
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const mobile=String(req.body?.mobile||'').trim(),password=String(req.body?.password||'');
    const r=await db.execute({sql:`SELECT ${cols},password_hash FROM users WHERE mobile=? OR (role='admin' AND username=?) LIMIT 1`,args:[mobile,mobile]});
    const u=r.rows[0];
    if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Invalid mobile number or password'});
    if(u.status==='blocked')return res.status(403).json({error:'Account blocked; contact admin'});
    if(u.role!=='admin'&&u.status!=='active')return res.status(403).json({error:'Account is waiting for admin approval'});
    await audit(u.mobile,'login',u.id,'Successful login');
    res.json({token:sign(u),user:pub(u)});
  }catch(e){console.error(e);res.status(500).json({error:'Login failed'})}
});
app.get('/api/me',auth,(req,res)=>res.json({user:pub(req.user)}));

// Broadcast image is stored as a small data-URL in Turso so Render does not
// need a writable filesystem. The public endpoint is intentionally cache-busted
// by the notification sender with the current update sequence.
app.get('/api/broadcast-image',async(req,res)=>{
  try{
    const c=await getConfig(['broadcast_image']);
    const raw=String(c.broadcast_image||'');
    const m=raw.match(/^data:(image\/(?:png|jpeg|jpg|webp));base64,([A-Za-z0-9+/=]+)$/i);
    if(!m)return res.status(404).end();
    const buf=Buffer.from(m[2],'base64');
    res.setHeader('Content-Type',m[1].toLowerCase()==='image/jpg'?'image/jpeg':m[1].toLowerCase());
    res.setHeader('Cache-Control','public,max-age=300');
    res.end(buf);
  }catch(e){res.status(500).end()}
});

// Version-1 compatible Screen 3 endpoint. It returns the currently
// authenticated user's Admin-assigned URL plus the current broadcast.
// This keeps the original Screen 3 contract while preserving per-user links.
app.get('/api/get-link',auth,async(req,res)=>{
  try{
    const c=await getConfig(['broadcast','broadcast_title','broadcast_link','broadcast_image','broadcast_update_seq']);
    const row=await db.execute({sql:'SELECT custom_link FROM users WHERE id=? AND role=\'user\' LIMIT 1',args:[req.user.id]});
    const url=(row.rows[0]?.custom_link||'').toString().trim();
    const image=String(c.broadcast_image||'');
    const imageUrl=image?`${req.protocol}://${req.get('host')}/api/broadcast-image?v=${Number(c.broadcast_update_seq||0)}`:'';
    res.json({url,broadcast:c.broadcast||'',broadcastTitle:c.broadcast_title||'Live Portal',broadcastLink:c.broadcast_link||'',broadcastImage:imageUrl});
  }catch(e){
    console.error(e);
    res.status(500).json({error:'Could not load Screen 3 link'});
  }
});

app.post('/api/push/token',auth,async(req,res)=>{
  try{
    const token=String(req.body?.token||'').trim();
    if(token.length<20||token.length>4096)return res.status(400).json({error:'Invalid device token'});
    // If this token was previously tied to another user on the same device, move it.
    await db.execute({sql:'DELETE FROM device_tokens WHERE token=? AND user_id<>?',args:[token,req.user.id]});
    await db.execute({sql:'INSERT OR IGNORE INTO device_tokens(id,user_id,token,created_at) VALUES(?,?,?,?)',args:[randomUUID(),req.user.id,token,new Date().toISOString()]});
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:'Could not save notification token'})}
});

app.delete('/api/push/token',auth,async(req,res)=>{
  try{const token=String(req.body?.token||'').trim();if(token)await db.execute({sql:'DELETE FROM device_tokens WHERE token=? AND user_id=?',args:[token,req.user.id]});res.json({ok:true})}catch(e){res.status(500).json({error:'Could not remove notification token'})}
});

app.get('/api/admin/users',auth,adminOnly,async(req,res)=>{
  try{
    let q=String(req.query.q||'').trim().slice(0,100),sql=`SELECT ${cols} FROM users WHERE role='user'`,args=[];
    if(q){sql+=' AND (name LIKE ? OR mobile LIKE ? OR email LIKE ?)';args=[`%${q}%`,`%${q}%`,`%${q}%`]}
    sql+=' ORDER BY created_at DESC LIMIT 2000';
    const r=await db.execute({sql,args});res.json({users:r.rows.map(pub)});
  }catch(e){res.status(500).json({error:'Could not load users'})}
});

app.patch('/api/admin/users/:id/status',auth,adminOnly,async(req,res)=>{
  const status=req.body?.status;
  if(!['pending','active','blocked'].includes(status))return res.status(400).json({error:'Invalid status'});
  try{
    const x=await db.execute({sql:"UPDATE users SET status=? WHERE id=? AND role='user'",args:[status,req.params.id]});
    if(!x.rowsAffected)return res.status(404).json({error:'User not found'});
    await audit(req.user.mobile,'status_changed',req.params.id,status);
    const r=await db.execute({sql:`SELECT ${cols} FROM users WHERE id=?`,args:[req.params.id]});
    res.json({user:pub(r.rows[0])});
  }catch(e){res.status(500).json({error:'Could not update status'})}
});

app.patch('/api/admin/users/:id/link',auth,adminOnly,async(req,res)=>{
  const link=String(req.body?.link||'').trim();
  if(link&&(!/^https:\/\//i.test(link)||link.length>2048))return res.status(400).json({error:'Link must be a valid HTTPS URL'});
  try{
    const x=await db.execute({sql:"UPDATE users SET custom_link=? WHERE id=? AND role='user'",args:[link,req.params.id]});
    if(!x.rowsAffected)return res.status(404).json({error:'User not found'});
    await audit(req.user.mobile,'custom_link_changed',req.params.id,link||'Link removed');
    res.json({ok:true,link});
  }catch(e){res.status(500).json({error:'Could not save link'})}
});

app.post('/api/admin/broadcast',auth,adminOnly,async(req,res)=>{
  const message=String(req.body?.message||'').trim().slice(0,1000);
  const title=String(req.body?.title||'Live Portal').trim().slice(0,80)||'Live Portal';
  const link=String(req.body?.link||'').trim();
  const image=String(req.body?.image||'').trim();
  if(!message)return res.status(400).json({error:'Broadcast message is empty'});
  if(link&&(!/^https:\/\//i.test(link)||link.length>2048))return res.status(400).json({error:'Broadcast link must be HTTPS'});
  if(image && !/^data:image\/(?:png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/i.test(image))return res.status(400).json({error:'Broadcast image must be a PNG, JPG or WEBP data image'});
  if(image && image.length>2200000)return res.status(413).json({error:'Broadcast image is too large; keep it under about 1.5 MB'});
  try{
    const seq=await bumpUpdate();
    await setConfig('broadcast',message);
    await setConfig('broadcast_title',title);
    await setConfig('broadcast_link',link);
    await setConfig('broadcast_image',image);
    await setConfig('broadcast_update_seq',seq);
    const t=await db.execute('SELECT token FROM device_tokens');
    const imageUrl=image?`${req.protocol}://${req.get('host')}/api/broadcast-image?v=${seq}`:'';
    const push=await sendPushToTokens(t.rows.map(x=>x.token),title,message,link,imageUrl);
    const status=push.status||'failed';
    await setConfig('broadcast_last_status',status);
    await setConfig('broadcast_last_sent',push.sent||0);
    await setConfig('broadcast_last_total',push.total||0);
    await setConfig('broadcast_last_failed',push.failed||0);
    await setConfig('broadcast_last_at',new Date().toISOString());
    await audit(req.user.mobile,'broadcast_sent','',`Broadcast ${status}: ${push.sent||0}/${push.total||0}, failed ${push.failed||0}`);
    res.json({ok:true,message:status==='sent'?'Broadcast sent successfully':status==='partial'?'Broadcast partially sent':status==='no_registered_devices'?'Saved, but no registered devices were available':'Broadcast saved but push delivery failed',updateSeq:seq,push:{...push,image:!!image,link:!!link}});
  }catch(e){console.error(e);res.status(500).json({error:'Could not send broadcast'})}
});

app.patch('/api/admin/maintenance',auth,adminOnly,async(req,res)=>{
  try{const enabled=!!req.body?.enabled;await setConfig('maintenance',enabled);await bumpUpdate();await audit(req.user.mobile,'maintenance_changed','',String(enabled));res.json({ok:true,maintenance:enabled})}
  catch(e){res.status(500).json({error:'Could not update maintenance mode'})}
});

app.patch('/api/admin/developer',auth,adminOnly,async(req,res)=>{
  try{
    const d=req.body?.developer;if(!d||typeof d!=='object')return res.status(400).json({error:'Developer details required'});
    await setConfig('developer_details',JSON.stringify({name:String(d.name||'').slice(0,120),course:String(d.course||'').slice(0,120),skills:Array.isArray(d.skills)?d.skills.map(x=>String(x).slice(0,80)).slice(0,30):[],friends:Array.isArray(d.friends)?d.friends.map(x=>String(x).slice(0,80)).slice(0,30):[]}));
    await bumpUpdate();await audit(req.user.mobile,'developer_details_changed','','Developer details updated');res.json({ok:true});
  }catch(e){res.status(500).json({error:'Could not update developer details'})}
});

app.patch('/api/admin/alert',auth,adminOnly,async(req,res)=>{
  try{
    const a=req.body?.alert||{};const link=String(a.link||'').trim();
    if(link&&(!/^https:\/\//i.test(link)||link.length>2048))return res.status(400).json({error:'Alert link must be HTTPS'});
    await setConfig('alert_enabled',!!a.enabled);
    await setConfig('alert_title',String(a.title||'').slice(0,120));
    await setConfig('alert_body',String(a.body||'').slice(0,2000));
    await setConfig('alert_link',link);
    const seq=await bumpUpdate();
    await audit(req.user.mobile,'alert_changed','','Startup alert updated');
    res.json({ok:true,updateSeq:seq});
  }catch(e){res.status(500).json({error:'Could not update alert'})}
});

app.get('/api/admin/settings',auth,adminOnly,async(_req,res)=>{
  try{
    const c=await getConfig(['alert_enabled','alert_title','alert_body','alert_link','developer_details']);
    let developer={name:'Sandeep Kumar',course:'BGS Second Semester',skills:[],friends:[]};
    try{if(c.developer_details)developer=JSON.parse(c.developer_details)}catch{}
    res.json({alert:{enabled:c.alert_enabled==='true',title:c.alert_title||'',body:c.alert_body||'',link:c.alert_link||''},developer});
  }catch(e){res.status(500).json({error:'Could not load settings'})}
});

app.get('/api/admin/reports',auth,adminOnly,async(_req,res)=>{
  try{
    const r=await db.execute("SELECT substr(created_at,1,10) day,COUNT(*) total FROM users WHERE role='user' AND created_at>=datetime('now','-30 days') GROUP BY substr(created_at,1,10) ORDER BY day DESC");
    const m=await db.execute("SELECT substr(created_at,1,7) month,COUNT(*) total FROM users WHERE role='user' GROUP BY substr(created_at,1,7) ORDER BY month DESC LIMIT 12");
    res.json({daily:r.rows,monthly:m.rows});
  }catch(e){res.status(500).json({error:'Could not load reports'})}
});

app.get('/api/admin/audit',auth,adminOnly,async(_q,s)=>{
  try{const r=await db.execute('SELECT actor,action,target,details,created_at FROM audit_log ORDER BY created_at DESC LIMIT 100');s.json({logs:r.rows})}
  catch(e){s.status(500).json({error:'Could not load activity log'})}
});

async function start(){
  await db.batch([
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,mobile TEXT NOT NULL UNIQUE,email TEXT NOT NULL DEFAULT '',username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','blocked')),created_at TEXT NOT NULL,custom_link TEXT NOT NULL DEFAULT '',phone_verified INTEGER NOT NULL DEFAULT 0)",
    'CREATE INDEX IF NOT EXISTS idx_users_role_created ON users(role,created_at DESC)',
    "CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL DEFAULT '')",
    'CREATE TABLE IF NOT EXISTS audit_log(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS device_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL)'
  ],'write');

  for(const sql of [
    "ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''"
  ]){try{await db.execute(sql)}catch(e){if(!String(e.message).toLowerCase().includes('duplicate column'))throw e}}
  await db.execute("UPDATE users SET username='u_'||replace(replace(replace(replace(mobile,'+',''),'-',''),' ',''),'(','') WHERE username=''");

  const adminMobile=process.env.ADMIN_MOBILE||'0000000000';
  const username=String(process.env.ADMIN_USERNAME).toLowerCase();
  const f=await db.execute({sql:"SELECT id FROM users WHERE role='admin' LIMIT 1"});
  if(!f.rows.length){
    const id=randomUUID(),hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12),now=new Date().toISOString();
    await db.execute({sql:'INSERT INTO users(id,name,mobile,email,username,password_hash,role,status,created_at,custom_link,phone_verified) VALUES(?,?,?,?,?,?,?,?,?,?,1)',args:[id,'Administrator',adminMobile,'',username,hash,'admin','active',now,'',1]});
    await audit('system','admin_created',id,username);
  }
  if(!(await getConfig(['languages'])).languages)await setConfig('languages',JSON.stringify(['Hindi','English','Bihari']));
  if(!(await getConfig(['developer_details'])).developer_details)await setConfig('developer_details',JSON.stringify({name:'Sandeep Kumar',course:'BGS Second Semester',skills:['Website Developer','App Developer','Android Developer','Full-Stack Developer','Frontend Developer','Backend Developer','API Developer','Database Developer','Bot Developer','Telegram Bot Developer','Automation Developer','UI/UX Developer','3D Website Developer','Cloud Deployment','Server Management','JavaScript Developer','Node.js Developer'],friends:['Niteesh','Pintu','Chhotu','Anil']}));
  if(!(await getConfig(['update_seq'])).update_seq)await setConfig('update_seq','0');
  app.listen(process.env.PORT||3000,()=>console.log('Live Portal backend running on '+(process.env.PORT||3000)));
}
start().catch(e=>{console.error(e);process.exit(1)});
