const ALLOWED_ORIGIN = "https://oestechevrolet.github.io";

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
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function unb64(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  return atob(
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4)
  );
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return b64url(
    String.fromCharCode(...new Uint8Array(signature))
  );
}

async function makeToken(secret) {
  const payload = b64url(
    JSON.stringify({
      exp: Date.now() + 8 * 60 * 60 * 1000,
    })
  );

  const signature = await sign(payload, secret);

  return payload + "." + signature;
}

async function validToken(request, env) {
  const authorization =
    request.headers.get("Authorization") || "";

  if (!authorization.startsWith("Bearer ")) {
    return false;
  }

  const token = authorization.slice(7);
  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [payload, signature] = parts;

  try {
    const data = JSON.parse(unb64(payload));

    if (!data.exp || data.exp < Date.now()) {
      return false;
    }

    const expected = await sign(
      payload,
      env.SESSION_SECRET
    );

    return expected === signature;
  } catch {
    return false;
  }
}

function getOrigin(env) {
  return env.PANEL_ORIGIN || ALLOWED_ORIGIN;
}

export default {
  async fetch(request, env) {
    const origin = getOrigin(env);
    const url = new URL(request.url);

    // CORS preflight.
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    try {
      // Health check.
      if (
        url.pathname === "/api/health" &&
        request.method === "GET"
      ) {
        return json(
          {
            ok: true,
            service: "oeste-marketing-api",
          },
          200,
          origin
        );
      }

      // Login.
      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        let body;

        try {
          body = await request.json();
        } catch {
          return json(
            { message: "JSON inválido." },
            400,
            origin
          );
        }

        const password = body?.password;

        if (
          !password ||
          password !== env.PANEL_PASSWORD
        ) {
          return json(
            { message: "Senha inválida." },
            401,
            origin
          );
        }

        if (!env.SESSION_SECRET) {
          return json(
            { message: "SESSION_SECRET não configurado." },
            500,
            origin
          );
        }

        return json(
          {
            token: await makeToken(
              env.SESSION_SECRET
            ),
          },
          200,
          origin
        );
      }

      // Todas as outras rotas exigem autenticação.
      if (!(await validToken(request, env))) {
        return json(
          { message: "Não autorizado." },
          401,
          origin
        );
      }

      // Buscar solicitações do Forminit.
      if (
        url.pathname === "/api/submissions" &&
        request.method === "GET"
      ) {
        if (
          !env.FORMINIT_API_KEY ||
          !env.FORMINIT_FORM_ID
        ) {
          return json(
            {
              message:
                "Configuração do Forminit incompleta.",
            },
            500,
            origin
          );
        }

        const formUrl = new URL(
          "https://api.forminit.com/v1/forms/" +
            env.FORMINIT_FORM_ID
        );

        formUrl.searchParams.set("size", "100");
        formUrl.searchParams.set("files", "true");
        formUrl.searchParams.set(
          "timezone",
          "America/Cuiaba"
        );

        const formResponse = await fetch(formUrl, {
          method: "GET",
          headers: {
            "X-API-Key": env.FORMINIT_API_KEY,
            Accept: "application/json",
          },
        });

        const formData =
          await formResponse.json().catch(() => ({}));

        if (!formResponse.ok) {
          return json(
            {
              message:
                formData?.message ||
                "Falha ao consultar Forminit.",
            },
            502,
            origin
          );
        }

        const submissions =
          formData?.data?.submissions || [];

        const ids = submissions
          .map((submission) => submission.id)
          .filter(Boolean);

        const statuses = {};

        if (ids.length && env.DB) {
          const placeholders = ids
            .map(() => "?")
            .join(",");

          const result = await env.DB
            .prepare(
              `SELECT submission_id, status, note
               FROM request_status
               WHERE submission_id IN (${placeholders})`
            )
            .bind(...ids)
            .all();

          for (const row of result.results || []) {
            statuses[row.submission_id] = row;
          }
        }

        return json(
          {
            submissions: submissions.map(
              (submission) => ({
                ...submission,
                panelStatus:
                  statuses[submission.id]?.status ||
                  "pending",
                panelNote:
                  statuses[submission.id]?.note ||
                  "",
              })
            ),
            pagination:
              formData?.data?.pagination || {},
          },
          200,
          origin
        );
      }

      // Atualizar status.
      if (
        url.pathname === "/api/status" &&
        request.method === "POST"
      ) {
        let body;

        try {
          body = await request.json();
        } catch {
          return json(
            { message: "JSON inválido." },
            400,
            origin
          );
        }

        const id = body?.id;
        const status = body?.status;
        const note = body?.note || "";

        const allowedStatuses = [
          "pending",
          "in_review",
          "approved",
          "rejected",
          "done",
        ];

        if (
          !id ||
          !allowedStatuses.includes(status)
        ) {
          return json(
            { message: "Status inválido." },
            400,
            origin
          );
        }

        if (!env.DB) {
          return json(
            { message: "Banco D1 não configurado." },
            500,
            origin
          );
        }

        await env.DB.prepare(
          `INSERT INTO request_status
             (submission_id, status, note, updated_at)
           VALUES (?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(submission_id)
           DO UPDATE SET
             status = excluded.status,
             note = excluded.note,
             updated_at = CURRENT_TIMESTAMP`
        )
          .bind(id, status, note)
          .run();

        return json(
          { ok: true },
          200,
          origin
        );
      }

      return json(
        { message: "Rota não encontrada." },
        404,
        origin
      );
    } catch (error) {
      return json(
        {
          message:
            error?.message ||
            "Erro interno no Worker.",
        },
        500,
        origin
      );
    }
  },
};
