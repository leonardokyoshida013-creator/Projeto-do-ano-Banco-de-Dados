# Sistema de Acesso Seguro com Painel ADM

Sistema web de autenticação e gestão de usuários com integração Firebase Firestore e camadas reforçadas de segurança criptográfica (OWASP).

## 🛡️ Camadas de Segurança Implementadas

- **Criptografia de Senhas (PBKDF2)**: Hashing com 100.000 iterações de HMAC-SHA-256 e Salt criptográfico de 16 bytes via Web Crypto API nativa do navegador. Nenhuma senha trafega ou é salva em texto claro.
- **Proteção contra Força Bruta (Rate Limiting)**: Bloqueio automático e temporário com contagem regressiva após 5 tentativas incorretas consecutivas.
- **Proteção contra XSS e Injeção**: Sanitização rigorosa de entidades HTML e validação estrita de papéis (RBAC).
- **Prevenção de Vazamento de Credenciais**: Métodos de listagem (`DB.getAll`) sanitizam completamente os dados, nunca expondo hashes ou salts.
- **Política de Senhas Fortes**: Exigência de pelo menos 8 caracteres com letras maiúsculas, minúsculas e números.
- **Expiração de Sessão por Inatividade**: Logout automático de segurança após 30 minutos sem atividade.
- **Cabeçalhos de Proteção (CSP & Referrer-Policy)**: Restrição de fontes e scripts permitidos na execução da página.
- **Regras Blindadas do Firestore**: Arquivo `firestore.rules` com validação de esquema de documentos.

## Contas ADM Padrão

| Usuário | Senha Padrão | Função |
|---|---|---|
| `leonardo` | `Leonardo12@` | Administrador |
| `abner` | `adm123` | Administrador |
| `isabela` | `adm123` | Administrador |
| `matheus` | `adm123` | Administrador |

> As credenciais padrão são armazenadas em forma de hash PBKDF2 com salt em `db.js`.

## Como Publicar no GitHub Pages

1. Crie ou acesse seu repositório no GitHub.
2. Faça upload dos arquivos:
   - `index.html`
   - `style.css`
   - `db.js` (com suas credenciais do Firebase)
   - `app.js`
   - `firestore.rules`
3. Configure o Firebase seguindo o guia passo a passo em [CONFIGURACAO_FIREBASE.md](file:///c:/Users/Leonardo.kyoshida/Downloads/Projeto-em-desenvolvimento--main/Projeto-em-desenvolvimento--main/CONFIGURACAO_FIREBASE.md).
4. No GitHub, vá em **Settings → Pages** → selecione a branch `main` e a pasta `/ (root)`.
5. Salve e acesse a URL gerada pelo GitHub Pages.

## Estrutura de Arquivos

```
index.html              → Estrutura da página, tags CSP e segurança
style.css               → Estilos visuais e responsividade
db.js                   → Camada de banco de dados (Firebase Firestore) com PBKDF2 e sanitização
app.js                  → Lógica da aplicação, rate limiting, RBAC e validação
firestore.rules         → Regras seguras de validação do banco Firestore
CONFIGURACAO_FIREBASE.md → Guia completo e seguro de configuração do Firebase
README.md               → Documentação do projeto
```
