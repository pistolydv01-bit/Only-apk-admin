require('dotenv').config();
const express=require('express');
const cors=require('cors');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {createClient}=require('@libsql/client');
const rateLimit=require('express-rate-limit');
const {randomUUID,randomInt}=require('crypto');

const required=['TURSO_DATABASE_URL','TURSO_AUTH_TOKEN','JWT_SECRET','ADMIN_USERNAME','ADMIN_PASSWORD'];
for(const k of required) if(!process.env[k]) throw new Error(`Missing required environment variable: ${k}`);
if(process.env.JWT_SECRET.length<32) throw new Error('JWT_SECRET must be at least 32 characters');
const db=createClient({url:process.env.TURSO_DATABASE_URL,authToken:process.env.TURSO_AUTH_TOKEN});
const app=express();
app.disable('x-powered-by');
app.use(cors({origin:process.env.CORS_ORIGIN||'*'}));
app.use(express.json({limit:'64kb'}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:80,standardHeaders:true,legacyHeaders:false}));

const cols='id,name,mobile,email,username,role,status,created_at,custom_link,phone_verified';
const pub=u=>({id:u.id,name:u.name,mobile:u.mobile,email:u.email||'',role:u.role,status:u.status,createdAt:u.created_at,customLink:u.custom_link||'',phoneVerified:!!u.phone_verified});
const sign=u=>jwt.sign({sub:u.id,role:u.role},process.env.JWT_SECRET,{expiresIn:'12h'});

async function auth(req,res,next){
  try{
    const h=req.headers.authorization||'';
    const p=jwt.verify(h.startsWith('Bearer ')?h.slice(7):'',process.env.JWT_SECRET);
    const r=await db.execute({sql:`SELECT ${cols} FROM users WHERE id=?`,args:[p.sub]});
    if(!r.rows[0]||r.rows[0].status==='blocked') return res.status(401).json({error:'Account unavailable'});
    req.user=r.rows[0]; next();
  }catch{return res.status(401).json({error:'Please log in again'});}
}
const adminOnly=(req,res,next)=>req.user?.role==='admin'?next():res.status(403).json({error:'Admin access required'});
async function audit(actor,action,target='',details=''){try{await db.execute({sql:'INSERT INTO audit_log(id,actor,action,target,details,created_at) VALUES(?,?,?,?,?,?)',args:[randomUUID(),actor,action,String(target).slice(0,200),String(details).slice(0,1000),new Date().toISOString()]});}catch(e){console.error('audit:',e.message)}}
async function getConfig(keys){
  const r=await db.execute({sql:`SELECT key,value FROM config WHERE key IN (${keys.map(()=>'?').join(',')})`,args:keys});
  return Object.fromEntries(r.rows.map(x=>[x.key,x.value]));
}
async function setConfig(key,value){await db.execute({sql:"INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",args:[key,String(value)]});}

// Telegram OTP registration flow.
// A Telegram bot cannot proactively DM an arbitrary username. The user must first
// open the bot (via the deep link) so Telegram gives us the user's chat_id.
function telegramBotUsername(){return String(process.env.TELEGRAM_BOT_USERNAME||'').replace(/^@/,'').trim()}
async function telegramSend(chatId,text,extra={}){
  const token=process.env.TELEGRAM_BOT_TOKEN;
  if(!token) throw new Error('Telegram bot is not configured');
  const r=await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:chatId,text,...extra})});
  const d=await r.json(); if(!r.ok||!d.ok) throw new Error(d.description||'Telegram send failed'); return d;
}
async function telegramAdmin(text){
  if(!process.env.TELEGRAM_BOT_TOKEN||!process.env.TELEGRAM_CHAT_ID)return;
  try{await telegramSend(process.env.TELEGRAM_CHAT_ID,text,{disable_web_page_preview:true})}catch(e){console.error('Telegram:',e.message)}
}
async function makeTelegramOtp(mobile,chatId,linkToken){
  const code=String(randomInt(100000,1000000));
  const hash=await bcrypt.hash(code,10);
  const now=Date.now();
  await db.execute({sql:'INSERT INTO otp_challenges(id,mobile,chat_id,link_token,code_hash,expires_at,attempts,used,created_at) VALUES(?,?,?,?,?,?,?,?,?)',args:[randomUUID(),mobile,chatId,linkToken,hash,new Date(now+10*60*1000).toISOString(),0,0,new Date(now).toISOString()]});
  await telegramSend(chatId,`Live Portal OTP: ${code}\n\nयह OTP 10 मिनट में expire हो जाएगा। इसे किसी दूसरे व्यक्ति के साथ share न करें।`);
}

app.post('/api/auth/telegram/start-registration',async(req,res)=>{
  try{
    const mobile=String(req.body?.mobile||'').trim();
    if(!/^\+?[1-9]\d{7,14}$/.test(mobile))return res.status(400).json({error:'Enter mobile number with country code, e.g. +9198xxxxxx'});
    if(!process.env.TELEGRAM_BOT_TOKEN||!telegramBotUsername())return res.status(503).json({error:'Telegram OTP is not configured on the server'});
    const ex=await db.execute({sql:'SELECT id FROM users WHERE mobile=?',args:[mobile]});
    if(ex.rows.length)return res.status(409).json({error:'Mobile number already registered'});
    const linkToken=jwt.sign({mobile,purpose:'telegram_link'},process.env.JWT_SECRET,{expiresIn:'15m'});
    await db.execute({sql:'INSERT INTO telegram_links(id,mobile,link_token,created_at,expires_at) VALUES(?,?,?,?,?)',args:[randomUUID(),mobile,linkToken,new Date().toISOString(),new Date(Date.now()+15*60*1000).toISOString()]});
    const bot=telegramBotUsername();
    res.json({ok:true,linkToken,botLink:`https://t.me/${bot}?start=${encodeURIComponent(linkToken)}`,message:'Open the Telegram bot link, tap Start, then return here and enter the OTP.'});
  }catch(e){console.error(e);res.status(500).json({error:'Could not start Telegram verification'})}
});

app.get('/api/auth/telegram/status',async(req,res)=>{
  try{
    const token=String(req.query.token||'');
    const p=jwt.verify(token,process.env.JWT_SECRET);
    if(p.purpose!=='telegram_link')throw new Error('Invalid link');
    const r=await db.execute({sql:'SELECT chat_id FROM telegram_links WHERE link_token=? AND expires_at>? ORDER BY created_at DESC LIMIT 1',args:[token,new Date().toISOString()]});
    res.json({linked:!!r.rows[0]?.chat_id});
  }catch(e){res.status(400).json({error:'Telegram link expired or invalid'})}
});

app.post('/api/auth/verify-registration-otp',async(req,res)=>{
  try{
    const mobile=String(req.body?.mobile||'').trim(),code=String(req.body?.code||'').trim(),linkToken=String(req.body?.linkToken||'');
    if(!mobile||!/^[0-9]{6}$/.test(code)||!linkToken)return res.status(400).json({error:'Enter the 6-digit Telegram OTP'});
    const p=jwt.verify(linkToken,process.env.JWT_SECRET);
    if(p.purpose!=='telegram_link'||p.mobile!==mobile)throw new Error('Invalid verification link');
    const r=await db.execute({sql:'SELECT * FROM otp_challenges WHERE link_token=? AND mobile=? AND used=0 ORDER BY created_at DESC LIMIT 1',args:[linkToken,mobile]});
    const ch=r.rows[0];
    if(!ch||new Date(ch.expires_at)<=new Date())return res.status(400).json({error:'OTP expired; request a new one'});
    if(Number(ch.attempts)>=5)return res.status(429).json({error:'Too many OTP attempts; request a new one'});
    const ok=await bcrypt.compare(code,ch.code_hash);
    await db.execute({sql:'UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?',args:[ch.id]});
    if(!ok)return res.status(400).json({error:'Invalid OTP'});
    await db.execute({sql:'UPDATE otp_challenges SET used=1 WHERE id=?',args:[ch.id]});
    const verificationToken=jwt.sign({mobile,purpose:'signup'},process.env.JWT_SECRET,{expiresIn:'10m'});
    res.json({ok:true,message:'Telegram verified',verificationToken});
  }catch(e){res.status(400).json({error:e.message==='jwt expired'?'Telegram verification link expired':'Telegram verification failed'})}
});

app.post('/telegram/webhook',async(req,res)=>{
  res.sendStatus(200);
  try{
    const msg=req.body?.message;
    const chatId=msg?.chat?.id;
    const text=String(msg?.text||'').trim();
    if(!chatId||!text.startsWith('/start'))return;
    const parts=text.split(/\s+/,2),linkToken=parts[1]||'';
    if(!linkToken)return telegramSend(chatId,'Live Portal में वापस जाएँ और Connect Telegram दबाएँ।');
    let p;try{p=jwt.verify(linkToken,process.env.JWT_SECRET)}catch{return telegramSend(chatId,'यह verification link expire हो चुका है। ऐप से नया link लें।')}
    if(p.purpose!=='telegram_link')return telegramSend(chatId,'Invalid verification link.');
    const r=await db.execute({sql:'SELECT id,mobile FROM telegram_links WHERE link_token=? AND expires_at>? ORDER BY created_at DESC LIMIT 1',args:[linkToken,new Date().toISOString()]});
    if(!r.rows[0])return telegramSend(chatId,'Verification link expire हो चुका है। ऐप से नया OTP request करें।');
    await db.execute({sql:'UPDATE telegram_links SET chat_id=?,telegram_username=? WHERE id=?',args:[String(chatId),msg.from?.username||'',r.rows[0].id]});
    await makeTelegramOtp(r.rows[0].mobile,String(chatId),linkToken);
  }catch(e){console.error('Telegram webhook:',e.message)}
});

// Firebase Cloud Messaging HTTP v1 for real Android notifications.
let googleAuth=null;
async function getFcmAccessToken(){
  if(!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) throw new Error('Firebase push is not configured');
  if(!googleAuth){
    const {GoogleAuth}=require('google-auth-library');
    const credentials=JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    googleAuth=new GoogleAuth({credentials,scopes:['https://www.googleapis.com/auth/firebase.messaging']});
  }
  const client=await googleAuth.getClient();
  const t=await client.getAccessToken();
  return typeof t==='string'?t:t.token;
}
async function sendPushToTokens(tokens,title,body,link=''){
  if(!tokens.length||!process.env.FIREBASE_PROJECT_ID) return {sent:0};
  let access; try{access=await getFcmAccessToken()}catch(e){console.error('FCM:',e.message);return {sent:0,error:e.message};}
  let sent=0;
  for(const token of [...new Set(tokens)]){
    try{
      const r=await fetch(`https://fcm.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT_ID}/messages:send`,{method:'POST',headers:{Authorization:`Bearer ${access}`,'content-type':'application/json'},body:JSON.stringify({message:{token,notification:{title,body},data:{link:String(link||'')}}})});
      if(r.ok) sent++; else console.error('FCM send failed',await r.text());
    }catch(e){console.error('FCM token error:',e.message)}
  }
  return {sent};
}

app.get('/health',(_q,s)=>s.json({ok:true,database:'turso',telegramOtp:!!process.env.TELEGRAM_BOT_TOKEN&&!!process.env.TELEGRAM_BOT_USERNAME,push:!!process.env.FIREBASE_PROJECT_ID}));

app.get('/api/config',async(_q,s)=>{
  try{
    const c=await getConfig(['broadcast','maintenance','alert_enabled','alert_title','alert_body','alert_link','developer_details','languages']);
    let developer={name:'Sandeep Kumar',course:'BGS Second Semester',skills:['Website Developer','App Developer','Android Developer','Full-Stack Developer','Frontend Developer','Backend Developer','API Developer','Database Developer','Bot Developer','Telegram Bot Developer','Automation Developer','UI/UX Developer','3D Website Developer','Cloud Deployment','Server Management','JavaScript Developer','Node.js Developer'],friends:['Niteesh','Pintu','Chhotu','Anil']};
    try{if(c.developer_details)developer=JSON.parse(c.developer_details)}catch{}
    s.json({broadcast:c.broadcast||'',maintenance:c.maintenance==='true',alert:{enabled:c.alert_enabled==='true',title:c.alert_title||'',body:c.alert_body||'',link:c.alert_link||''},developer,languages:c.languages?JSON.parse(c.languages):['Hindi','English','Bihari']});
  }catch(e){console.error(e);s.status(500).json({error:'Could not load config'})}
});

app.post('/api/auth/register',async(req,res)=>{
  try{
    const {name,mobile,email='',password,verificationToken}=req.body||{};
    if(typeof name!=='string'||!name.trim()||typeof mobile!=='string'||!mobile.trim()||typeof password!=='string'||password.length<10||password.length>128)return res.status(400).json({error:'Enter valid name, mobile and a 10–128 character password'});
    if(typeof email!=='string'||email.length>254)return res.status(400).json({error:'Invalid email'});
    try{const vp=jwt.verify(String(verificationToken||''),process.env.JWT_SECRET);if(vp.purpose!=='signup'||vp.mobile!==mobile.trim())return res.status(400).json({error:'Mobile verification required'})}catch{return res.status(400).json({error:'Mobile verification expired; request a new OTP'})}
    let ex=await db.execute({sql:'SELECT id FROM users WHERE mobile=?',args:[mobile.trim()]});
    if(ex.rows.length)return res.status(409).json({error:'Mobile number already registered'});
    let id=randomUUID(),hash=await bcrypt.hash(password,12),now=new Date().toISOString(),username='u_'+mobile.replace(/\D/g,'');
    await db.execute({sql:'INSERT INTO users(id,name,mobile,email,username,password_hash,role,status,created_at,custom_link,phone_verified) VALUES(?,?,?,?,?,?,?,?,?,?,1)',args:[id,name.trim(),mobile.trim(),email.trim().toLowerCase(),username,hash,'user','pending',now,'']});
    await audit('system','user_registered',id,`${name.trim()}, mobile ${mobile.trim()}`);
    await telegramAdmin(`New registration\nName: ${name.trim()}\nMobile: ${mobile.trim()}\nStatus: pending`);
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

app.post('/api/push/token',auth,async(req,res)=>{
  try{const token=String(req.body?.token||'').trim();if(token.length<20||token.length>4096)return res.status(400).json({error:'Invalid device token'});await db.execute({sql:'INSERT OR IGNORE INTO device_tokens(id,user_id,token,created_at) VALUES(?,?,?,?)',args:[randomUUID(),req.user.id,token,new Date().toISOString()]});res.json({ok:true})}catch(e){res.status(500).json({error:'Could not save notification token'})}
});

app.get('/api/admin/users',auth,adminOnly,async(req,res)=>{
  try{let q=String(req.query.q||'').trim().slice(0,100),sql=`SELECT ${cols} FROM users WHERE role='user'`,args=[];if(q){sql+=' AND (name LIKE ? OR mobile LIKE ? OR email LIKE ?)';args=[`%${q}%`,`%${q}%`,`%${q}%`]}sql+=' ORDER BY created_at DESC LIMIT 2000';let r=await db.execute({sql,args});res.json({users:r.rows.map(pub)})}catch(e){res.status(500).json({error:'Could not load users'})}
});
app.patch('/api/admin/users/:id/status',auth,adminOnly,async(req,res)=>{let status=req.body?.status;if(!['pending','active','blocked'].includes(status))return res.status(400).json({error:'Invalid status'});try{let x=await db.execute({sql:"UPDATE users SET status=? WHERE id=? AND role='user'",args:[status,req.params.id]});if(!x.rowsAffected)return res.status(404).json({error:'User not found'});await audit(req.user.mobile,'status_changed',req.params.id,status);let r=await db.execute({sql:`SELECT ${cols} FROM users WHERE id=?`,args:[req.params.id]});res.json({user:pub(r.rows[0])})}catch(e){res.status(500).json({error:'Could not update status'})}});
app.patch('/api/admin/users/:id/link',auth,adminOnly,async(req,res)=>{let link=String(req.body?.link||'').trim();if(link&&(!/^https:\/\//i.test(link)||link.length>2048))return res.status(400).json({error:'Link must be a valid HTTPS URL'});try{let x=await db.execute({sql:"UPDATE users SET custom_link=? WHERE id=? AND role='user'",args:[link,req.params.id]});if(!x.rowsAffected)return res.status(404).json({error:'User not found'});await audit(req.user.mobile,'custom_link_changed',req.params.id,link||'Link removed');res.json({ok:true,link})}catch(e){res.status(500).json({error:'Could not save link'})}});

app.post('/api/admin/broadcast',auth,adminOnly,async(req,res)=>{
  const message=String(req.body?.message||'').trim().slice(0,1000); if(!message)return res.status(400).json({error:'Broadcast message is empty'});
  try{
    await setConfig('broadcast',message); await audit(req.user.mobile,'broadcast_updated','','Broadcast message updated');
    let pushed={sent:0};
    const title=String(req.body?.title||'Live Portal').slice(0,80);
    const link=String(req.body?.link||'').trim();
    const t=await db.execute('SELECT token FROM device_tokens');
    pushed=await sendPushToTokens(t.rows.map(x=>x.token),title,message,link);
    if(req.body?.telegram===true)await telegramAdmin(`Admin broadcast:\n${message}${link?'\n'+link:''}`);
    res.json({ok:true,message:'Broadcast saved and notification sent',push:pushed});
  }catch(e){console.error(e);res.status(500).json({error:'Could not send broadcast'})}
});

app.patch('/api/admin/maintenance',auth,adminOnly,async(req,res)=>{try{let enabled=!!req.body?.enabled;await setConfig('maintenance',enabled);await audit(req.user.mobile,'maintenance_changed','',String(enabled));res.json({ok:true,maintenance:enabled})}catch(e){res.status(500).json({error:'Could not update maintenance mode'})}});
app.patch('/api/admin/developer',auth,adminOnly,async(req,res)=>{try{const d=req.body?.developer;if(!d||typeof d!=='object')return res.status(400).json({error:'Developer details required'});await setConfig('developer_details',JSON.stringify({name:String(d.name||'').slice(0,120),course:String(d.course||'').slice(0,120),skills:Array.isArray(d.skills)?d.skills.map(x=>String(x).slice(0,80)).slice(0,30):[],friends:Array.isArray(d.friends)?d.friends.map(x=>String(x).slice(0,80)).slice(0,30):[]}));await audit(req.user.mobile,'developer_details_changed','','Developer details updated');res.json({ok:true})}catch(e){res.status(500).json({error:'Could not update developer details'})}});
app.patch('/api/admin/alert',auth,adminOnly,async(req,res)=>{try{const a=req.body?.alert||{};await setConfig('alert_enabled',!!a.enabled);await setConfig('alert_title',String(a.title||'').slice(0,120));await setConfig('alert_body',String(a.body||'').slice(0,2000));const link=String(a.link||'').trim();if(link&&(!/^https:\/\//i.test(link)||link.length>2048))return res.status(400).json({error:'Alert link must be HTTPS'});await setConfig('alert_link',link);await audit(req.user.mobile,'alert_changed','','Startup alert updated');res.json({ok:true})}catch(e){res.status(500).json({error:'Could not update alert'})}});
app.get('/api/admin/settings',auth,adminOnly,async(_req,res)=>{try{const c=await getConfig(['alert_enabled','alert_title','alert_body','alert_link','developer_details']);let developer={name:'Sandeep Kumar',course:'BGS Second Semester',skills:[],friends:[]};try{if(c.developer_details)developer=JSON.parse(c.developer_details)}catch{}res.json({alert:{enabled:c.alert_enabled==='true',title:c.alert_title||'',body:c.alert_body||'',link:c.alert_link||''},developer})}catch(e){res.status(500).json({error:'Could not load settings'})}});
app.get('/api/admin/reports',auth,adminOnly,async(req,res)=>{try{let r=await db.execute("SELECT substr(created_at,1,10) day,COUNT(*) total FROM users WHERE role='user' AND created_at>=datetime('now','-30 days') GROUP BY substr(created_at,1,10) ORDER BY day DESC"),m=await db.execute("SELECT substr(created_at,1,7) month,COUNT(*) total FROM users WHERE role='user' GROUP BY substr(created_at,1,7) ORDER BY month DESC LIMIT 12");res.json({daily:r.rows,monthly:m.rows})}catch(e){res.status(500).json({error:'Could not load reports'})}});
app.get('/api/admin/audit',auth,adminOnly,async(_q,s)=>{try{let r=await db.execute('SELECT actor,action,target,details,created_at FROM audit_log ORDER BY created_at DESC LIMIT 100');s.json({logs:r.rows})}catch(e){s.status(500).json({error:'Could not load activity log'})}});

async function start(){
  await db.batch([
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,mobile TEXT NOT NULL UNIQUE,email TEXT NOT NULL DEFAULT '',username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','blocked')),created_at TEXT NOT NULL,custom_link TEXT NOT NULL DEFAULT '',phone_verified INTEGER NOT NULL DEFAULT 0)",
    'CREATE INDEX IF NOT EXISTS idx_users_role_created ON users(role,created_at DESC)',
    "CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL DEFAULT '')",
    'CREATE TABLE IF NOT EXISTS audit_log(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS device_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS telegram_links(id TEXT PRIMARY KEY,mobile TEXT NOT NULL,link_token TEXT NOT NULL UNIQUE,chat_id TEXT,telegram_username TEXT,created_at TEXT NOT NULL,expires_at TEXT NOT NULL)',
    'CREATE TABLE IF NOT EXISTS otp_challenges(id TEXT PRIMARY KEY,mobile TEXT NOT NULL,chat_id TEXT NOT NULL,link_token TEXT NOT NULL,code_hash TEXT NOT NULL,expires_at TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL)' 
  ],'write');
  // Additive migrations for older databases.
  for(const sql of ["ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0","ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''"]){try{await db.execute(sql)}catch(e){if(!String(e.message).toLowerCase().includes('duplicate column'))throw e}}
  await db.execute("UPDATE users SET username='u_'||replace(replace(replace(replace(mobile,'+',''),'-',''),' ',''),'(','') WHERE username=''");
  const adminMobile=process.env.ADMIN_MOBILE||'0000000000';
  const username=String(process.env.ADMIN_USERNAME).toLowerCase();
  const f=await db.execute({sql:'SELECT id FROM users WHERE role=\'admin\' LIMIT 1'});
  if(!f.rows.length){const id=randomUUID(),hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12),now=new Date().toISOString();await db.execute({sql:'INSERT INTO users(id,name,mobile,email,username,password_hash,role,status,created_at,custom_link,phone_verified) VALUES(?,?,?,?,?,?,?,?,?,?,1)',args:[id,'Administrator',adminMobile,'',username,hash,'admin','active',now,'',1]});await audit('system','admin_created',id,username)}
  await setConfig('languages',JSON.stringify(['Hindi','English','Bihari']));
  if(!(await getConfig(['developer_details'])).developer_details) await setConfig('developer_details',JSON.stringify({name:'Sandeep Kumar',course:'BGS Second Semester',skills:['Website Developer','App Developer','Android Developer','Full-Stack Developer','Frontend Developer','Backend Developer','API Developer','Database Developer','Bot Developer','Telegram Bot Developer','Automation Developer','UI/UX Developer','3D Website Developer','Cloud Deployment','Server Management','JavaScript Developer','Node.js Developer'],friends:['Niteesh','Pintu','Chhotu','Anil']}));
  app.listen(process.env.PORT||3000,()=>console.log('Live Portal backend running on '+(process.env.PORT||3000)));
}
start().catch(e=>{console.error(e);process.exit(1)});
