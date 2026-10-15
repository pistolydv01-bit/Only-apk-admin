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
app.get('/health',(_q,s)=>s.json({ok:true,database:'turso',push:!!process.env.FIREBASE_PROJECT_ID}));

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
    const {name,mobile,email='',password}=req.body||{};
    if(typeof name!=='string'||!name.trim()||typeof mobile!=='string'||!mobile.trim()||typeof password!=='string'||password.length<10||password.length>128)return res.status(400).json({error:'Enter valid name, mobile and a 10–128 character password'});
    if(typeof email!=='string'||email.length>254)return res.status(400).json({error:'Invalid email'});
    let ex=await db.execute({sql:'SELECT id FROM users WHERE mobile=?',args:[mobile.trim()]});
    if(ex.rows.length)return res.status(409).json({error:'Mobile number already registered'});
    let id=randomUUID(),hash=await bcrypt.hash(password,12),now=new Date().toISOString(),username='u_'+mobile.replace(/\D/g,'');
    await db.execute({sql:'INSERT INTO users(id,name,mobile,email,username,password_hash,role,status,created_at,custom_link,phone_verified) VALUES(?,?,?,?,?,?,?,?,?,?,1)',args:[id,name.trim(),mobile.trim(),email.trim().toLowerCase(),username,hash,'user','pending',now,'']});
    await audit('system','user_registered',id,`${name.trim()}, mobile ${mobile.trim()}`);

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
    'CREATE TABLE IF NOT EXISTS device_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL)',);
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
