# Backend do Painel de Marketing

O GitHub Pages hospeda apenas a interface. A API do Forminit exige uma chave secreta e a própria documentação orienta que ela nunca seja exposta em JavaScript público. Por isso, este backend deve ser hospedado em um Worker/Pages Function com secrets protegidos.

## 1. Criar D1

No terminal:
npx wrangler d1 create oeste-marketing

Copie o database_id para wrangler.toml e aplique:
npx wrangler d1 execute oeste-marketing --remote --file=./schema.sql

## 2. Configurar secrets

No Worker, crie:
FORMINIT_API_KEY = sua chave da API do Forminit
PANEL_PASSWORD = senha do diretor
SESSION_SECRET = uma string longa e aleatória

A documentação do Cloudflare recomenda armazenar chaves e tokens como Secrets, não em arquivos públicos.

## 3. Configurar

Copie wrangler.toml.example para wrangler.toml e coloque o ID da D1.

## 4. Publicar

A partir de backend/:
npx wrangler deploy

Depois copie a URL do Worker e coloque no início de js/painel.js:
window.MARKETING_API_BASE = "https://SEU-WORKER.workers.dev";

## Segurança

Não coloque a API key do Forminit no GitHub, em HTML ou JavaScript público. O Forminit exige X-API-Key para a API de submissões e recomenda uso exclusivamente server-side.
