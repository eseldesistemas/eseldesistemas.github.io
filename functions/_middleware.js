// Cloudflare Pages middleware. Configurar secretos y protección Cloudflare Access antes de activar.
const enc=new TextEncoder();
const headers={"cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer"};
function json(obj,status=200,extra={}){return new Response(JSON.stringify(obj),{status,headers:{"content-type":"application/json; charset=utf-8",...headers,...extra}})}
function redirect(){return new Response(null,{status:303,headers:{location:"/login",...headers}})}
function login(){
const page='<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Ingresar · Es el de Sistemas</title><style>*{box-sizing:border-box}body{font:15px system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7f7;color:#252525}main{background:white;width:min(92vw,390px);padding:34px;border:1px solid #e4e4e4;border-radius:20px;text-align:center;box-shadow:0 10px 30px #0000000b}h1{font-size:23px;margin:0 0 12px}p{color:#747474;margin-bottom:28px}input{width:100%;font-size:24px;letter-spacing:.6em;text-align:center;padding:15px;border-radius:12px;border:1px solid #ccc}button{margin-top:15px;width:100%;background:#f6b821;color:#242424;border:0;border-radius:12px;padding:14px;font-size:15px;font-weight:700;cursor:pointer}.msg{color:#9d1f1f;min-height:24px;margin-top:14px;font-size:13px}</style></head><body><main><h1>Es el de Sistemas</h1><form id="f"><label for="pin" style="position:absolute;clip-path:inset(50%);width:1px;height:1px;overflow:hidden">Código de acceso</label><input id="pin" type="password" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" required autofocus><button>Ingresar</button></form><div class="msg" id="message" role="alert"></div></main><script>document.querySelector("#f").addEventListener("submit",async function(ev){ev.preventDefault();const b=this.querySelector("button");b.disabled=true;try{const r=await fetch("/api/login",{method:"POST",credentials:"same-origin",headers:{"content-type":"application/json"},body:JSON.stringify({pin:document.querySelector("#pin").value})});document.querySelector("#pin").value="";if(r.ok){location.replace("/");return}document.querySelector("#message").textContent=r.status===429?"Demasiados intentos. Probá más tarde.":r.status===503?"Acceso aún no configurado.":"Código incorrecto."}catch{document.querySelector("#message").textContent="No se pudo conectar."}finally{b.disabled=false}});</script></body></html>';
return new Response(page,{status:200,headers:{"content-type":"text/html; charset=utf-8","content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",...headers}});
}
const b64=(bytes)=>btoa(String.fromCharCode(...bytes)).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
const unb64=(s)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
async function hkey(secret){return crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"])}
async function sign(payload,secret){const raw=enc.encode(JSON.stringify(payload));const mac=await crypto.subtle.sign("HMAC",await hkey(secret),raw);return b64(raw)+"."+b64(new Uint8Array(mac))}
async function authenticated(request,secret){
try{const cookie=request.headers.get("cookie")||"";const value=cookie.match(/(?:^|;\s*)eds_session=([^;]+)/)?.[1];if(!value)return false;const [payload,mac]=value.split(".");if(!payload||!mac)return false;const raw=unb64(payload);if(!await crypto.subtle.verify("HMAC",await hkey(secret),unb64(mac),raw))return false;const session=JSON.parse(new TextDecoder().decode(raw));return session.v===1&&Number.isFinite(session.exp)&&session.exp>Date.now()}catch{return false}
}
export async function onRequest(ctx){
const {request,env}=ctx,url=new URL(request.url),path=url.pathname;
const configured=/^[0-9]{6}$/.test(env.PIN_SECRET||"")&&typeof env.SESSION_SECRET==="string"&&env.SESSION_SECRET.length>=32&&!!env.SECURITY_DB;
if(!configured)return json({error:"Falta configurar secretos o base D1 SECURITY_DB"},503);
if(path==="/login"&&request.method==="GET"){return await authenticated(request,env.SESSION_SECRET)?new Response(null,{status:303,headers:{location:"/",...headers}}):login()}
if(path==="/api/login"){
 if(request.method!=="POST")return json({error:"Método no permitido"},405);
 // Control de intentos en D1 por identificador HMAC de la IP. El IP original no se almacena.
 // Cinco intentos por ventana de 15 minutos, contando también los intentos exitosos.
 const ip=request.headers.get("cf-connecting-ip")||"unknown";
 const ipSignature=await crypto.subtle.sign("HMAC",await hkey(env.SESSION_SECRET),enc.encode("rate:"+ip));
 const clientKey=b64(new Uint8Array(ipSignature));
 const now=Date.now(),windowLimit=now-15*60*1000;
 let count;
 try{
  const result=await env.SECURITY_DB.prepare(
   "INSERT INTO login_attempts (client_key, window_start, attempts) VALUES (?1, ?2, 1) "+
   "ON CONFLICT(client_key) DO UPDATE SET "+
   "attempts=CASE WHEN login_attempts.window_start<=?3 THEN 1 ELSE login_attempts.attempts+1 END, "+
   "window_start=CASE WHEN login_attempts.window_start<=?3 THEN excluded.window_start ELSE login_attempts.window_start END "+
   "RETURNING attempts"
  ).bind(clientKey,now,windowLimit).first();
  count=result?.attempts;
 }catch{return json({error:"Control de acceso temporalmente no disponible"},503)}
 if(!Number.isInteger(count))return json({error:"Control de acceso no disponible"},503);
 if(count>5)return json({error:"Demasiados intentos"},429);
 let body;try{body=await request.json()}catch{return json({error:"Solicitud inválida"},400)}
 if(typeof body.pin!=="string"||!/^[0-9]{6}$/.test(body.pin))return json({error:"Código incorrecto"},401);
 // Comparación por HMAC (sin almacenar PIN en el cliente ni en el repositorio).
 const secretKey=await hkey(env.SESSION_SECRET);
 const token=await crypto.subtle.sign("HMAC",secretKey,enc.encode(body.pin));
 const valid=await crypto.subtle.verify("HMAC",secretKey,token,enc.encode(env.PIN_SECRET));
 if(!valid)return json({error:"Código incorrecto"},401);
 const session=await sign({v:1,exp:Date.now()+5*60*1000},env.SESSION_SECRET);
 return json({ok:true},200,{"set-cookie":"eds_session="+session+"; HttpOnly; Secure; SameSite=Strict; Path=/"});
}
if(path==="/api/logout"&&request.method==="POST")return new Response(null,{status:204,headers:{"set-cookie":"eds_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",...headers}});
if(!await authenticated(request,env.SESSION_SECRET)){return path.startsWith("/api/")?json({error:"Sin autorización"},401):redirect()}
// Renovación solo tras actividad real del usuario (la web la llama con interacción).
if(path==="/api/session"){
 if(request.method!=="POST")return json({error:"Método no permitido"},405);
 const session=await sign({v:1,exp:Date.now()+5*60*1000},env.SESSION_SECRET);
 return json({ok:true},200,{"set-cookie":"eds_session="+session+"; HttpOnly; Secure; SameSite=Strict; Path=/"});
}
if(path==="/api/private-links"){
 if(request.method!=="GET")return json({error:"Método no permitido"},405);
 if(!env.PRIVATE_LINKS_JSON)return json({error:"Enlaces personales no configurados"},503);
 try{const links=JSON.parse(env.PRIVATE_LINKS_JSON);if(!Array.isArray(links))throw Error("invalid");
 return json({links:links.filter(x=>x&&typeof x.source==="string"&&typeof x.url==="string"&&x.url.startsWith("https://"))})}
 catch{return json({error:"Configuración inválida"},503)}
}
if(path.startsWith("/api/"))return json({error:"No encontrado"},404);
const response=await ctx.next();
const h=new Headers(response.headers);h.set("cache-control","private, no-store");h.set("referrer-policy","no-referrer");h.set("x-content-type-options","nosniff");
return new Response(response.body,{status:response.status,headers:h});
}