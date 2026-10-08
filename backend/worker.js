const ALLOWED_ORIGIN = "https://oestechevrolet.github.io";
const DEFAULT_MARKETING_EMAIL = "marketing@oesteveiculos.com.br";
const DEFAULT_FROM_EMAIL = "marketing@oesteveiculos.com.br";
const WORKER_VERSION = "panel-cleanup-v1";

async function ensureDriveColumn(env) {
  if (!env.DB) return;
  const columns = await env.DB.prepare("PRAGMA table_info(request_status)").all();
  if (!(columns.results || []).some(c => c.name === "drive_url")) {
    await env.DB.prepare("ALTER TABLE request_status ADD COLUMN drive_url TEXT").run();
  }
}

async function ensureFileUrlsColumn(env) {
  if (!env.DB) return;
  const columns = await env.DB.prepare("PRAGMA table_info(request_status)").all();
  if (!(columns.results || []).some(c => c.name === "file_urls")) {
    await env.DB.prepare("ALTER TABLE request_status ADD COLUMN file_urls TEXT").run();
  }
}

async function ensureDeletedColumn(env) {
  if (!env.DB) return;
  const columns = await env.DB.prepare("PRAGMA table_info(request_status)").all();
  if (!(columns.results || []).some(c => c.name === "deleted_at")) {
    await env.DB.prepare("ALTER TABLE request_status ADD COLUMN deleted_at TEXT").run();
  }
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(data, status = 200, origin = ALLOWED_ORIGIN) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      ...corsHeaders(origin),
    },
  });
}

function b64url(input) {
  return btoa(input).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  return atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64url(String.fromCharCode(...new Uint8Array(signature)));
}

async function makeToken(secret, role, username) {
  const payload = b64url(JSON.stringify({exp: Date.now() + 8 * 60 * 60 * 1000, role, username}));
  return payload + "." + await sign(payload, secret);
}

async function validToken(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) return null;
  const parts = authorization.slice(7).split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  try {
    const data = JSON.parse(unb64(payload));
    if (!data.exp || data.exp < Date.now() || !["marketing","director"].includes(data.role)) return null;
    const expected = await sign(payload, env.SESSION_SECRET);
    return expected === signature ? data : null;
  } catch {
    return null;
  }
}

function getOrigin(env) {
  return env.PANEL_ORIGIN || ALLOWED_ORIGIN;
}

function field(blocks, ...keys) {
  for (const key of keys) {
    const value = blocks?.[key];
    if (value !== undefined && value !== null && value !== "") {
      return Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);
    }
  }
  return "";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#39;");
}

function getRequester(submission) {
  const b = submission?.blocks || {};
  return {
    name: field(b,"fi-text-nome_solicitante","nome_solicitante") || field(b.sender,"fullName") || "Solicitante",
    concessionaria: field(b,"fi-select-concessionaria","concessionaria") || "",
    email: field(b,"fi-email-email_retorno","email_retorno") || field(b.sender,"email"),
    phone: field(b,"fi-phone-telefone","telefone") || field(b.sender,"phone"),
  };
}

function getCampaign(submission) {
  const b = submission?.blocks || {};
  return field(b,"fi-text-nome_campanha","nome_campanha") || "Sem campanha";
}

function normalizeFiles(submission) {
  const urls = [];
  const add = (item) => {
    if (!item) return;
    if (Array.isArray(item)) {
      item.forEach(add);
      return;
    }
    if (typeof item === "string") {
      if (item.startsWith("http://") || item.startsWith("https://")) urls.push(item);
      return;
    }
    if (typeof item !== "object") return;

    const direct = item.url || item.file || item.downloadUrl || item.download_url || item.href || item.link;
    if (typeof direct === "string" && (direct.startsWith("http://") || direct.startsWith("https://"))) {
      urls.push(direct);
      return;
    }

    for (const value of Object.values(item)) add(value);
  };

  add(submission?.files);
  add(submission?.attachments);

  const blocks = submission?.blocks || {};
  for (const [key, value] of Object.entries(blocks)) {
    if (/file|arquivo|attachment|anexo/i.test(key)) add(value);
  }

  return [...new Set(urls)].map(url => ({url}));
}

function extractWebhookFileUrls(data) {
  const urls = [];
  const add = (item) => {
    if (!item) return;
    if (Array.isArray(item)) {
      item.forEach(add);
      return;
    }
    if (typeof item === "string") {
      if (item.startsWith("http://") || item.startsWith("https://")) urls.push(item);
      return;
    }
    if (typeof item !== "object") return;

    const direct = item.file || item.url;
    if (typeof direct === "string" && (direct.startsWith("http://") || direct.startsWith("https://"))) {
      urls.push(direct);
      return;
    }

    for (const value of Object.values(item)) add(value);
  };

  for (const [key, value] of Object.entries(data || {})) {
    if (/file|arquivo|attachment|anexo/i.test(key)) add(value);
  }

  return [...new Set(urls)].map(url => ({url}));
}

function storedFiles(row) {
  if (!row?.file_urls) return [];
  try {
    const parsed = JSON.parse(row.file_urls);
    return Array.isArray(parsed) ? parsed.filter(item => item?.url) : [];
  } catch {
    return [];
  }
}

async function verifyForminitWebhook(request, rawBody, env) {
  const secret = env.FORMINIT_WEBHOOK_SECRET;
  if (!secret) return true;

  const webhookId = request.headers.get("Forminit-Webhook-Id") || "";
  const timestamp = request.headers.get("Forminit-Webhook-Timestamp") || "";
  const signature = request.headers.get("Forminit-Webhook-Signature") || "";
  if (!webhookId || !/^\d+$/.test(timestamp) || !/^v1=[a-f0-9]{64}$/.test(signature)) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (age > 300) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {name:"HMAC",hash:"SHA-256"},
    false,
    ["sign"]
  );
  const signed = "v1." + webhookId + "." + timestamp + "." + rawBody;
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signed));
  const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2,"0")).join("");
  return signature.slice(3) === hex;
}

function buildDemandRows(submission) {
  const b = submission?.blocks || {};
  const rows = [
    ["Concessionária", field(b,"fi-select-concessionaria","concessionaria")],
    ["Solicitante", field(b,"fi-text-nome_solicitante","nome_solicitante") || field(b.sender,"fullName")],
    ["E-mail", field(b,"fi-email-email_retorno","email_retorno") || field(b.sender,"email")],
    ["Telefone", field(b,"fi-phone-telefone","telefone") || field(b.sender,"phone")],
    ["Prazo", field(b,"fi-date-data_entrega","data_entrega")],
    ["Prioridade", field(b,"fi-radio-prioridade","prioridade") || "Normal"],
    ["Material", field(b,"fi-checkbox-tipo_material[]","tipo_material")],
    ["Canais", field(b,"fi-checkbox-canais_divulgacao[]","canais_divulgacao")],
    ["Veículo", field(b,"fi-select-modelo_veiculo","modelo_veiculo")],
    ["Versão / ano", [field(b,"fi-text-versao_veiculo","versao_veiculo"),field(b,"fi-text-ano_modelo","ano_modelo")].filter(Boolean).join(" · ")],
    ["Condição comercial", field(b,"fi-radio-possui_oferta","possui_oferta")],
    ["Preço à vista", field(b,"fi-text-preco_vista","preco_vista")],
    ["Objetivo", field(b,"fi-text-objetivo","objetivo")],
    ["Descrição", field(b,"fi-text-descricao_demanda","descricao_demanda")],
    ["Observações", field(b,"fi-text-observacoes_finais","observacoes_finais")]
  ];
  return rows.filter(([,value]) => value).map(([label,value]) => '<tr><td style="padding:8px 10px;border:1px solid #dce6ed;font-weight:700;width:180px">'+escapeHtml(label)+'</td><td style="padding:8px 10px;border:1px solid #dce6ed">'+escapeHtml(value)+'</td></tr>').join("");
}

function buildFiles(submission) {
  return (submission?.files || []).map(file => {
    const url = file.url || file.downloadUrl || file.download_url;
    return url ? '<li><a href="'+escapeHtml(url)+'">'+escapeHtml(file.name || "Arquivo")+'</a></li>' : "";
  }).filter(Boolean).join("");
}

async function fetchSubmission(env, id) {
  if (!env.FORMINIT_API_KEY || !env.FORMINIT_FORM_ID) {
    throw new Error("Configuração do Forminit incompleta.");
  }
  let page = 1;
  while (page <= 50) {
    const formUrl = new URL("https://api.forminit.com/v1/forms/" + env.FORMINIT_FORM_ID);
    formUrl.searchParams.set("page", String(page));
    formUrl.searchParams.set("size", "100");
    formUrl.searchParams.set("files", "true");
    formUrl.searchParams.set("timezone", "America/Cuiaba");
    const response = await fetch(formUrl,{headers:{"X-API-Key":env.FORMINIT_API_KEY,Accept:"application/json"}});
    const data = await response.json().catch(()=>({}));
    if (!response.ok) throw new Error(data?.message || "Falha ao consultar Forminit.");
    const submissions = data?.data?.submissions || [];
    const found = submissions.find(item => item.id === id);
    if (found) {
      if (env.DB) {
        await ensureFileUrlsColumn(env);
        const row = await env.DB.prepare("SELECT file_urls FROM request_status WHERE submission_id=?").bind(id).first();
        if ((!Array.isArray(found.files) || !found.files.length) && row?.file_urls) {
          found.files = storedFiles(row);
        }
      }
      return found;
    }
    const pagination = data?.data?.pagination || {};
    if (!pagination.lastPage || page >= pagination.lastPage) break;
    page++;
  }
  throw new Error("Solicitação não encontrada no Forminit.");
}

async function sendEmail(env,{to,subject,html,replyTo,idempotencyKey}) {
  if (!env.RESEND_API_KEY) throw new Error("RESEND_API_KEY não configurado no Worker.");
  const from = env.EMAIL_FROM || DEFAULT_FROM_EMAIL;
  const payload = {from,to:[to],subject,html};
  if (replyTo) payload.reply_to = [replyTo];
  const response = await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{
      "Authorization":"Bearer "+env.RESEND_API_KEY,
      "Content-Type":"application/json",
      "Idempotency-Key":idempotencyKey
    },
    body:JSON.stringify(payload)
  });
  const data = await response.json().catch(()=>({}));
  if (!response.ok) throw new Error(data?.message || data?.error || "Falha ao enviar e-mail.");
  return data;
}

function emailLayout(title, intro, body) {
  return '<div style="font-family:Arial,Helvetica,sans-serif;background:#f3f7fa;padding:28px;color:#193244"><div style="max-width:720px;margin:auto;background:#fff;border:1px solid #dce6ed;border-radius:14px;padding:28px"><div style="font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#0b2e4f">Oeste Chevrolet · Painel de Marketing</div><h1 style="color:#0b2e4f;font-size:24px;margin:12px 0 8px">'+escapeHtml(title)+'</h1><p style="line-height:1.6">'+escapeHtml(intro)+'</p>'+body+'</div></div>';
}

function statusEmail(env,submission,status,extra) {
  const campaign = getCampaign(submission);
  const requester = getRequester(submission);
  const rows = buildDemandRows(submission);
  const files = buildFiles(submission);
  const fileBlock = files ? '<h3 style="color:#0b2e4f">Arquivos</h3><ul>'+files+'</ul>' : "";
  if (status === "in_review") {
    return {
      to: requester.email,
      replyTo: env.MARKETING_EMAIL || DEFAULT_MARKETING_EMAIL,
      subject: "[Oeste Chevrolet] Solicitação em análise — " + campaign,
      html: emailLayout("Sua solicitação está em análise", "Olá "+requester.name+". Recebemos sua demanda e ela está agora em análise pela equipe responsável.", '<p><strong>Campanha:</strong> '+escapeHtml(campaign)+'</p><p>Você receberá uma nova comunicação quando houver uma decisão.</p><h3 style="color:#0b2e4f">Resumo da demanda</h3><table style="width:100%;border-collapse:collapse">'+rows+"</table>")
    };
  }
  if (status === "approved") {
    const to = env.MARKETING_EMAIL || DEFAULT_MARKETING_EMAIL;
    return {
      to,
      replyTo: requester.email,
      subject: "[Marketing] Nova demanda aprovada — " + campaign,
      html: emailLayout("Nova demanda aprovada", "A solicitação abaixo foi aprovada no Painel de Marketing e está liberada para execução.", '<p><strong>Campanha:</strong> '+escapeHtml(campaign)+'</p><table style="width:100%;border-collapse:collapse">'+rows+"</table>"+fileBlock)
    };
  }
  if (status === "rejected") {
    const director = extra.directorName;
    const note = extra.note;
    return {
      to: requester.email,
      replyTo: env.MARKETING_EMAIL || DEFAULT_MARKETING_EMAIL,
      subject: "[Oeste Chevrolet] Solicitação reprovada — " + campaign,
      html: emailLayout("Sua solicitação foi reprovada", "Olá "+requester.name+". A solicitação abaixo não foi aprovada neste momento.", '<p><strong>Campanha:</strong> '+escapeHtml(campaign)+'</p><div style="margin:18px 0;padding:16px;background:#fdeaea;border-left:4px solid #bd3030;border-radius:8px"><strong>Mensagem do diretor '+escapeHtml(director)+':</strong><p style="white-space:pre-wrap;margin-bottom:0">'+escapeHtml(note)+'</p></div><h3 style="color:#0b2e4f">Resumo da demanda</h3><table style="width:100%;border-collapse:collapse">'+rows+"</table>")
    };
  }
  if (status === "done") {
    const driveUrl = extra.driveUrl || "";
    const driveBlock = driveUrl ? '<div style="margin:20px 0;padding:18px;background:#eef6fb;border:1px solid #cfe3f0;border-radius:10px"><strong style="color:#0b2e4f">Materiais da demanda</strong><p style="margin:8px 0 14px">Os materiais finais estão disponíveis na pasta do Google Drive.</p><a href="'+escapeHtml(driveUrl)+'" style="display:inline-block;background:#0b2e4f;color:#fff;text-decoration:none;padding:11px 16px;border-radius:8px;font-weight:700">Abrir materiais no Google Drive</a></div>' : "";
    return {
      to: requester.email,
      replyTo: env.MARKETING_EMAIL || DEFAULT_MARKETING_EMAIL,
      subject: "[Oeste Chevrolet] Solicitação concluída — " + campaign,
      html: emailLayout("Sua solicitação foi concluída", "Olá "+requester.name+". A equipe de Marketing informou que a demanda foi concluída.", '<p><strong>Campanha:</strong> '+escapeHtml(campaign)+'</p>'+driveBlock)
    };
  }
  return null;
}

export default {
  async fetch(request, env) {
    const origin = getOrigin(env);
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers:corsHeaders(origin)});
    try {
      if (url.pathname === "/api/health" && request.method === "GET") return json({ok:true,service:"oeste-marketing-api",version:WORKER_VERSION},200,origin);

      if (url.pathname === "/api/login" && request.method === "POST") {
        let body;
        try { body = await request.json(); } catch { return json({message:"JSON inválido."},400,origin); }
        const username=String(body?.username||"").trim().toLowerCase();
        const password=String(body?.password||"");
        let role="";
        if (username===String(env.MARKETING_USERNAME||"").trim().toLowerCase() && password===env.MARKETING_PASSWORD) role="marketing";
        if (username===String(env.DIRECTOR_USERNAME||"").trim().toLowerCase() && password===env.DIRECTOR_PASSWORD) role="director";
        if (!role) return json({message:"Usuário ou senha inválidos."},401,origin);
        if (!env.SESSION_SECRET) return json({message:"SESSION_SECRET não configurado."},500,origin);
        return json({token:await makeToken(env.SESSION_SECRET,role,username),role,username},200,origin);
      }

      if (url.pathname === "/api/forminit-webhook" && request.method === "POST") {
        const rawBody = await request.text();
        if (!(await verifyForminitWebhook(request, rawBody, env))) {
          return json({message:"Webhook inválido."},401,origin);
        }
        let payload;
        try { payload = JSON.parse(rawBody); } catch { return json({message:"JSON inválido."},400,origin); }
        if (payload?.event !== "form.submitted" || !payload?.id) {
          return json({received:true},200,origin);
        }
        if (!env.DB) return json({message:"Banco D1 não configurado."},500,origin);
        await ensureFileUrlsColumn(env);
        const files = extractWebhookFileUrls(payload.data || {});
        await env.DB.prepare(
          "INSERT INTO request_status (submission_id,status,note,drive_url,file_urls,updated_at) VALUES (?, 'pending', '', '', ?, CURRENT_TIMESTAMP) ON CONFLICT(submission_id) DO UPDATE SET file_urls=excluded.file_urls,updated_at=CURRENT_TIMESTAMP"
        ).bind(payload.id, JSON.stringify(files)).run();
        return json({received:true,files:files.length},200,origin);
      }

      const session=await validToken(request,env);
      if (!session) return json({message:"Não autorizado."},401,origin);

      if (url.pathname === "/api/submissions" && request.method === "GET") {
        await ensureDriveColumn(env);
        await ensureFileUrlsColumn(env);
        await ensureDeletedColumn(env);
        if (!env.FORMINIT_API_KEY || !env.FORMINIT_FORM_ID) return json({message:"Configuração do Forminit incompleta."},500,origin);
        const formUrl = new URL("https://api.forminit.com/v1/forms/"+env.FORMINIT_FORM_ID);
        formUrl.searchParams.set("size","100");
        formUrl.searchParams.set("files","true");
        formUrl.searchParams.set("timezone","America/Cuiaba");
        const formResponse = await fetch(formUrl,{headers:{"X-API-Key":env.FORMINIT_API_KEY,Accept:"application/json"}});
        const formData = await formResponse.json().catch(()=>({}));
        if (!formResponse.ok) return json({message:formData?.message||"Falha ao consultar Forminit."},502,origin);
        const submissions=formData?.data?.submissions||[];
        const ids=submissions.map(s=>s.id).filter(Boolean);
        const statuses={};
        if(ids.length&&env.DB){
          const placeholders=ids.map(()=>"?").join(",");
          const result=await env.DB.prepare("SELECT submission_id,status,note,drive_url,file_urls,deleted_at FROM request_status WHERE submission_id IN ("+placeholders+")").bind(...ids).all();
          for(const row of result.results||[]) statuses[row.submission_id]=row;
        }
        const visibleSubmissions=submissions.filter(s=>!statuses[s.id]?.deleted_at);
        return json({submissions:visibleSubmissions.map(s=>{
          const apiFiles=Array.isArray(s.files)?s.files:normalizeFiles(s);
          const files=apiFiles.length?apiFiles:storedFiles(statuses[s.id]);
          return {...s,panelStatus:statuses[s.id]?.status||"pending",panelNote:statuses[s.id]?.note||"",driveUrl:statuses[s.id]?.drive_url||"",files};
        }),pagination:formData?.data?.pagination||{}},200,origin);
      }

      if (url.pathname === "/api/delete" && request.method === "POST") {
        await ensureDeletedColumn(env);
        if (!env.DB) return json({message:"Banco D1 não configurado."},500,origin);
        let body;
        try { body = await request.json(); } catch { return json({message:"JSON inválido."},400,origin); }
        const id=String(body?.id||"").trim();
        if(!id) return json({message:"Solicitação inválida."},400,origin);
        const submission=await env.DB.prepare("SELECT submission_id FROM request_status WHERE submission_id=?").bind(id).first();
        if(!submission){
          await env.DB.prepare("INSERT INTO request_status (submission_id,status,note,drive_url,updated_at,deleted_at) VALUES (?, 'pending', '', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)").bind(id).run();
        } else {
          await env.DB.prepare("UPDATE request_status SET deleted_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE submission_id=?").bind(id).run();
        }
        return json({ok:true,deleted:true,id},200,origin);
      }

      if (url.pathname === "/api/drive" && request.method === "POST") {
        if (session.role !== "marketing") return json({message:"Acesso restrito à equipe de Marketing."},403,origin);
        await ensureDriveColumn(env);
        if (!env.DB) return json({message:"Banco D1 não configurado."},500,origin);
        let body;
        try { body = await request.json(); } catch { return json({message:"JSON inválido."},400,origin); }
        const id=body?.id,driveUrl=String(body?.driveUrl||"").trim();
        if(!id) return json({message:"Solicitação inválida."},400,origin);
        if(driveUrl){
          try { const parsed=new URL(driveUrl); if(!["drive.google.com","docs.google.com"].includes(parsed.hostname)) throw new Error(); }
          catch { return json({message:"Informe um link válido do Google Drive."},400,origin); }
        }
        await env.DB.prepare("INSERT INTO request_status (submission_id,status,note,drive_url,updated_at) VALUES (?, COALESCE((SELECT status FROM request_status WHERE submission_id=?),'pending'), COALESCE((SELECT note FROM request_status WHERE submission_id=?),''), ?, CURRENT_TIMESTAMP) ON CONFLICT(submission_id) DO UPDATE SET drive_url=excluded.drive_url,updated_at=CURRENT_TIMESTAMP").bind(id,id,id,driveUrl).run();
        return json({ok:true,driveUrl},200,origin);
      }

      if (url.pathname === "/api/status" && request.method === "POST") {
        let body;
        try { body = await request.json(); } catch { return json({message:"JSON inválido."},400,origin); }
        const id=body?.id,status=body?.status,note=String(body?.note||"").trim(),directorName=String(body?.directorName||"").trim(),driveUrl=String(body?.driveUrl||"").trim();
        const allowedByRole={marketing:["in_review","done"],director:["in_review","approved","rejected"]};
        if(!id||!allowedByRole[session.role]?.includes(status)) return json({message:"Você não tem permissão para este status."},403,origin);
        if(!env.DB) return json({message:"Banco D1 não configurado."},500,origin);

        const currentResult=await env.DB.prepare("SELECT status,updated_at FROM request_status WHERE submission_id=?").bind(id).first();
        const previousStatus=currentResult?.status||"pending";
        const previousUpdatedAt=currentResult?.updated_at||"never";
        if(previousStatus===status) return json({ok:true,unchanged:true,status},200,origin);

        if(status==="rejected" && (!directorName || !note)) return json({message:"Para reprovar, informe o nome do diretor e a mensagem ao solicitante."},400,origin);
        if(status==="done" && !driveUrl) return json({message:"Informe e salve o link do Google Drive antes de concluir a demanda."},400,origin);
        if(driveUrl){
          try { const parsed=new URL(driveUrl); if(!["drive.google.com","docs.google.com"].includes(parsed.hostname)) throw new Error(); }
          catch { return json({message:"Informe um link válido do Google Drive."},400,origin); }
        }

        const submission=await fetchSubmission(env,id);
        const email=statusEmail(env,submission,status,{directorName,note,driveUrl});
        if(!email || !email.to) return json({message:"Não foi possível determinar o destinatário do e-mail."},400,origin);
        const emailIdempotencyKey="status-"+status+"-"+id+"-"+previousUpdatedAt;
        await sendEmail(env,{...email,idempotencyKey:emailIdempotencyKey});

        await env.DB.prepare(`INSERT INTO request_status (submission_id,status,note,drive_url,updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(submission_id) DO UPDATE SET status=excluded.status,note=excluded.note,drive_url=excluded.drive_url,updated_at=CURRENT_TIMESTAMP`).bind(id,status,note,driveUrl).run();

        return json({ok:true,status,emailSent:true},200,origin);
      }

      return json({message:"Rota não encontrada."},404,origin);
    } catch(error) {
      return json({message:error?.message||"Erro interno no Worker."},500,origin);
    }
  }
};