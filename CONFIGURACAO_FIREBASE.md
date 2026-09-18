# 🔥 Como configurar o Firebase (passo a passo seguro)

## Por que Firebase?
O localStorage só existe no navegador local — não sincroniza entre dispositivos.
O Firebase Firestore é um banco de dados na nuvem gratuito que resolve isso.

---

## PASSO 1 — Criar o projeto no Firebase

1. Acesse https://console.firebase.google.com
2. Clique em **"Criar um projeto"**
3. Dê um nome (ex: `banco-seguro`) e clique em **Continuar**
4. Desative o Google Analytics (não precisa) → **Criar projeto**

---

## PASSO 2 — Criar o banco Firestore

1. No menu lateral esquerdo, clique em **"Firestore Database"**
2. Clique em **"Criar banco de dados"**
3. Selecione **"Iniciar no modo de produção"** → Avançar
4. Escolha a região mais próxima (ex: `southamerica-east1`) → **Ativar**

---

## PASSO 3 — Registrar o app Web

1. Na página inicial do projeto, clique no ícone **`</>`** (Web)
2. Dê um apelido (ex: `banco-seguro-web`) → **Registrar app**
3. Você verá um bloco como este:

```js
const firebaseConfig = {
  apiKey: "AIzaSy...",
  authDomain: "banco-seguro.firebaseapp.com",
  projectId: "banco-seguro",
  storageBucket: "banco-seguro.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abc123"
};
```

4. **Copie esses valores** e cole no arquivo `db.js` no bloco `firebaseConfig`.

---

## PASSO 4 — Configurar as Regras de Segurança (Proteção do Banco)

> ⚠️ **Atenção sobre Segurança:** Nunca utilize `allow read, write: if true;` em produção. Regras abertas permitem que qualquer usuário apague ou adultere documentos. Utilize as regras blindadas abaixo (também disponíveis no arquivo `firestore.rules`):

1. No menu lateral do Firebase Console, vá em **Firestore Database → Regras**
2. **Apague** o conteúdo atual e cole as regras a seguir:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function isValidUsername(username) {
      return username is string 
        && username.size() >= 3 
        && username.size() <= 30 
        && username.matches('^[a-zA-Z0-9._-]+$');
    }

    function isValidRole(role) {
      return role == 'user' || role == 'adm';
    }

    function isValidUserDoc(data) {
      return data.keys().hasAll(['id', 'name', 'username', 'role', 'createdAt'])
        && data.id is string
        && data.name is string && data.name.size() > 0 && data.name.size() <= 100
        && data.username is string && isValidUsername(data.username)
        && isValidRole(data.role)
        && (
          (data.keys().hasAll(['passwordHash', 'salt']) && data.passwordHash is string && data.salt is string)
          || (data.keys().hasAll(['password']) && data.password is string)
        );
    }

    function isValidNoteDoc(data) {
      return data.keys().hasAll(['text'])
        && data.text is string
        && data.text.size() <= 50000;
    }

    match /usuarios/{username} {
      allow read: if true;
      allow create: if isValidUsername(username) 
                    && request.resource.data.username == username
                    && isValidUserDoc(request.resource.data);
      allow update: if isValidUsername(username) 
                    && request.resource.data.username == username
                    && isValidUserDoc(request.resource.data);
      allow delete: if resource.data.role != 'adm';
    }

    match /notas/{username} {
      allow read: if true;
      allow create, update: if isValidUsername(username) 
                            && isValidNoteDoc(request.resource.data);
      allow delete: if true;
    }
  }
}
```

3. Clique em **Publicar**.

---

## PASSO 5 — Subir os arquivos no GitHub Pages

Faça upload dos arquivos para o repositório:
- `index.html`
- `style.css`
- `db.js` (com criptografia PBKDF2 e configurações)
- `app.js` (com rate limiting e validações de segurança)
- `firestore.rules` (regras do banco)

Em **Settings → Pages → Source**, selecione `main` / `root` e salve.

---

## 🔒 Melhorias de Segurança Implementadas no Código

1. **Criptografia de Senhas com PBKDF2 + Salt**: Nenhuma senha é salva em texto puro. Cada senha possui um salt único gerado com `crypto.getRandomValues` e 100.000 iterações de hashing SHA-256.
2. **Prevenção de Vazamento de Dados**: Métodos como `getAll()` e `findByUsername()` eliminam hashes e salts antes de retornar dados para a aplicação.
3. **Proteção contra Ataques de Força Bruta (Rate Limiting)**: Bloqueio progressivo após 5 tentativas incorretas de login.
4. **Prevenção contra XSS e Injeção**: Sanitização rigorosa de caracteres especiais e escape de entidades HTML.
5. **Política de Senhas Fortes**: Exigência de pelo menos 8 caracteres, maiúsculas, minúsculas e números.
6. **Controle de Acesso Baseado em Papéis (RBAC)**: Bloqueio no código para evitar ações de ADM executadas por usuários comuns.
7. **Timeout de Sessão por Inatividade**: Encerramento automático de sessão após 30 minutos sem atividade.
8. **Cabeçalhos de Segurança (CSP & Referrer Policy)**: Prevenção contra injeção de scripts maliciosos e clickjacking.
