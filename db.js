// ============================================================
//  db.js — Banco de dados Firebase Firestore com Segurança Criptográfica
//  - Senhas protegidas com PBKDF2-HMAC-SHA-256 (100.000 iterações + Salt)
//  - Sanitização de dados: nenhuma senha ou hash é exposto na listagem
//  - Migração automática transparente de senhas legadas
//  - Prevenção de escalonamento de privilégios e validação de entrada
// ============================================================

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import {
  getFirestore, collection, doc, getDoc, getDocs,
  setDoc, deleteDoc
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// =====================================================
//  ⚙️  CONFIGURAÇÃO DO FIREBASE
// =====================================================
const firebaseConfig = {
  apiKey: "AIzaSyDbCZZtRHDn_BXOSOSCk54g62izOTyFFYc",
  authDomain: "banco-seguro-1aa9b.firebaseapp.com",
  projectId: "banco-seguro-1aa9b",
  storageBucket: "banco-seguro-1aa9b.firebasestorage.app",
  messagingSenderId: "247629826149",
  appId: "1:247629826149:web:0af77cbada0f263da1de8c"
};
// =====================================================

const app = initializeApp(firebaseConfig);
const db  = getFirestore(app);

const USERS_COL  = "usuarios";
const NOTES_COL  = "notas";
const PBKDF2_ITERATIONS = 100000;

// ---------- Funções Criptográficas (Web Crypto API Nativa) ----------

function generateSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hashPassword(password, saltHex, iterations = PBKDF2_ITERATIONS) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const salt = hexToBytes(saltHex);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return bufferToHex(derivedBits);
}

// Comparação em tempo constante para mitigar ataques de temporização (Timing Attacks)
function constantTimeEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Higieniza dados de usuário para nunca expor senhas ou hashes para a interface
function sanitizeUser(u) {
  if (!u) return null;
  return {
    id: String(u.id || ''),
    name: String(u.name || '').trim(),
    username: String(u.username || '').toLowerCase().trim(),
    role: u.role === 'adm' ? 'adm' : 'user',
    createdAt: String(u.createdAt || '')
  };
}

// Usuários ADM padrão com senhas criptografadas (PBKDF2 + salt aleatório)
// Senhas originais: Leonardo -> 'Leonardo12@' | abner, isabela, matheus -> 'adm123'
const DEFAULT_USERS = [
  {
    id: "1",
    name: "Leonardo",
    username: "leonardo",
    passwordHash: "36ba688431ced3eb254af303d7dd6dbf2ffbc0b461de4ddf12fa3011f5a5a84c",
    salt: "fcbbc14cb7e185ffb3203f65df4636c5",
    iterations: PBKDF2_ITERATIONS,
    algorithm: "PBKDF2-SHA256",
    role: "adm",
    createdAt: "27/05/2025"
  },
  {
    id: "2",
    name: "Abner",
    username: "abner",
    passwordHash: "5f30cf2c7ff1ec1dc0bab077a4eaf1a41c8ae1ab3692afd41519059b90cb1d92",
    salt: "ff259a1398888c62e7c1e42f354fe35c",
    iterations: PBKDF2_ITERATIONS,
    algorithm: "PBKDF2-SHA256",
    role: "adm",
    createdAt: "27/05/2025"
  },
  {
    id: "3",
    name: "Isabela",
    username: "isabela",
    passwordHash: "fa2fc12be4dcbaa360fed02509c37b39b7742a1997080e097d6cb1c1f031d9b8",
    salt: "3c8da68864451b00bcfec362d35ac56d",
    iterations: PBKDF2_ITERATIONS,
    algorithm: "PBKDF2-SHA256",
    role: "adm",
    createdAt: "27/05/2025"
  },
  {
    id: "4",
    name: "Matheus",
    username: "matheus",
    passwordHash: "2f700e5a6211a3dd47f451c23045bb0dbb5b82e97e3089cb53e395cbf583d966",
    salt: "01d5cd668a1c155da602c2ac1ec2b39e",
    iterations: PBKDF2_ITERATIONS,
    algorithm: "PBKDF2-SHA256",
    role: "adm",
    createdAt: "27/05/2025"
  }
];

// ============================================================
//  Objeto DB seguro
// ============================================================
const DB = {

  // ---- Busca documento bruto interno (apenas para autenticação) ----
  async _getUserDoc(username) {
    if (!username) return null;
    const ref = doc(db, USERS_COL, String(username).toLowerCase().trim());
    const snap = await getDoc(ref);
    return snap.exists() ? snap.data() : null;
  },

  // ---- Inicialização segura: cria ADMs padrão e migra legados ----
  async init() {
    try {
      for (const u of DEFAULT_USERS) {
        const ref = doc(db, USERS_COL, u.username);
        const snap = await getDoc(ref);
        if (!snap.exists()) {
          await setDoc(ref, u);
        } else {
          const existing = snap.data();
          // Migração de segurança: se a conta existente ainda estiver em texto puro, atualiza para hash
          if (existing.password && !existing.passwordHash) {
            const salt = generateSalt();
            const hash = await hashPassword(existing.password, salt);
            const upgraded = {
              ...existing,
              passwordHash: hash,
              salt,
              iterations: PBKDF2_ITERATIONS,
              algorithm: "PBKDF2-SHA256"
            };
            delete upgraded.password;
            await setDoc(ref, upgraded);
          }
        }
      }
    } catch (err) {
      console.warn("Aviso na inicialização do DB:", err);
    }
  },

  // ---- Listar todos os usuários (estritamente sanitizados, sem senhas/hashes) ----
  async getAll() {
    const snap = await getDocs(collection(db, USERS_COL));
    return snap.docs.map(d => sanitizeUser(d.data())).filter(Boolean);
  },

  // ---- Buscar usuário por username (sanitizado) ----
  async findByUsername(username) {
    const userDoc = await this._getUserDoc(username);
    return userDoc ? sanitizeUser(userDoc) : null;
  },

  // ---- Autenticação segura com suporte a PBKDF2 e migração automática ----
  async authenticate(username, password) {
    if (!username || !password) return null;
    const cleanUsername = String(username).toLowerCase().trim();
    const userDoc = await this._getUserDoc(cleanUsername);
    if (!userDoc) return null;

    const ref = doc(db, USERS_COL, cleanUsername);

    // Caso 1: Usuário já possui hash seguro (PBKDF2)
    if (userDoc.passwordHash && userDoc.salt) {
      const iterations = userDoc.iterations || PBKDF2_ITERATIONS;
      const computedHash = await hashPassword(password, userDoc.salt, iterations);
      if (constantTimeEquals(computedHash, userDoc.passwordHash)) {
        return sanitizeUser(userDoc);
      }
      return null;
    }

    // Caso 2: Conta legada em texto claro -> autentica e migra imediatamente para hash
    if (userDoc.password && constantTimeEquals(password, userDoc.password)) {
      try {
        const salt = generateSalt();
        const hash = await hashPassword(password, salt);
        const upgraded = {
          ...userDoc,
          passwordHash: hash,
          salt,
          iterations: PBKDF2_ITERATIONS,
          algorithm: "PBKDF2-SHA256"
        };
        delete upgraded.password;
        await setDoc(ref, upgraded);
      } catch (e) {
        console.warn("Falha ao migrar senha legada:", e);
      }
      return sanitizeUser(userDoc);
    }

    return null;
  },

  // ---- Criar usuário de forma segura ----
  async createUser({ name, username, password, role = "user" }) {
    const cleanName = String(name || '').trim();
    const cleanUsername = String(username || '').toLowerCase().trim();

    // Validação estrita de formato de nome e usuário
    if (!cleanName || cleanName.length > 100) {
      return { ok: false, error: "Nome completo inválido (máximo de 100 caracteres)." };
    }

    const USERNAME_REGEX = /^[a-zA-Z0-9._-]{3,30}$/;
    if (!USERNAME_REGEX.test(cleanUsername)) {
      return { ok: false, error: "Nome de usuário inválido. Deve ter entre 3 e 30 caracteres (apenas letras, números, '.', '_' ou '-')." };
    }

    // Validação de força de senha
    if (typeof password !== 'string' || password.length < 8) {
      return { ok: false, error: "A senha deve conter ao menos 8 caracteres." };
    }
    if (!/[A-Z]/.test(password)) {
      return { ok: false, error: "A senha deve conter ao menos uma letra maiúscula." };
    }
    if (!/[a-z]/.test(password)) {
      return { ok: false, error: "A senha deve conter ao menos uma letra minúscula." };
    }
    if (!/[0-9]/.test(password)) {
      return { ok: false, error: "A senha deve conter ao menos um número." };
    }

    const existing = await this._getUserDoc(cleanUsername);
    if (existing) return { ok: false, error: "Nome de usuário já existe." };

    // Calcula próximo ID de forma segura
    const allUsers = await this.getAll();
    const maxId = allUsers.reduce((m, u) => Math.max(m, parseInt(u.id) || 0), 0);

    // Gera salt aleatório e calcula o hash criptográfico PBKDF2
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    const safeRole = role === "adm" ? "adm" : "user";

    const newUserDoc = {
      id:           String(maxId + 1),
      name:         cleanName,
      username:     cleanUsername,
      passwordHash: passwordHash,
      salt:         salt,
      iterations:   PBKDF2_ITERATIONS,
      algorithm:    "PBKDF2-SHA256",
      role:         safeRole,
      createdAt:    new Date().toLocaleDateString("pt-BR"),
    };

    await setDoc(doc(db, USERS_COL, cleanUsername), newUserDoc);
    return { ok: true, user: sanitizeUser(newUserDoc) };
  },

  // ---- Remover usuário ----
  async deleteUser(id) {
    const snap = await getDocs(collection(db, USERS_COL));
    const targetDoc = snap.docs.find(d => String(d.data().id) === String(id));
    if (targetDoc) {
      const data = targetDoc.data();
      // Não permite a exclusão de administradores
      if (data.role === 'adm') {
        throw new Error("Contas com privilégio de administrador não podem ser removidas.");
      }
      await deleteDoc(doc(db, USERS_COL, data.username.toLowerCase()));
      await deleteDoc(doc(db, NOTES_COL, data.username.toLowerCase()));
    }
  },

  // ---- Estatísticas seguras ----
  async stats() {
    const users = await this.getAll();
    return {
      total: users.length,
      adm:   users.filter(u => u.role === "adm").length,
      user:  users.filter(u => u.role === "user").length,
    };
  },

  // ---- Bloco de notas com validação de limite ----
  async getNotes(username) {
    if (!username) return "";
    const clean = String(username).toLowerCase().trim();
    const ref = doc(db, NOTES_COL, clean);
    const snap = await getDoc(ref);
    return snap.exists() ? (snap.data().text || "") : "";
  },

  async saveNotes(username, text) {
    if (!username) throw new Error("Usuário obrigatório");
    const clean = String(username).toLowerCase().trim();
    // Limita o tamanho a 50.000 caracteres para mitigar abusos de armazenamento
    const safeText = typeof text === 'string' ? text.slice(0, 50000) : "";
    await setDoc(doc(db, NOTES_COL, clean), {
      text: safeText,
      updatedAt: new Date().toISOString()
    });
  },
};

// Inicializa ADMs padrão com segurança e exporta
await DB.init();
export { DB };
