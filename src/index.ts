// budgeteer-api/src/index.ts
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import admin from "firebase-admin";
import { PrismaClient, Prisma } from "@prisma/client";
import aiRouter from "./routes/ai";

const prisma = new PrismaClient();

/* ----------------------------- Firebase Admin ---------------------------- */
(function initFirebase() {
  try {
    const svcJson = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (svcJson) {
      const svc = JSON.parse(svcJson);
      admin.initializeApp({ credential: admin.credential.cert(svc as admin.ServiceAccount) });
      return;
    }
    if (
      process.env.FIREBASE_PROJECT_ID &&
      process.env.FIREBASE_CLIENT_EMAIL &&
      process.env.FIREBASE_PRIVATE_KEY
    ) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
        }),
      });
      return;
    }
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
  } catch (e) {
    console.error("Firebase init error:", e);
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
  }
})();

/* -------------------------------- Flinks -------------------------------- */
// Modes: "mock" | "sandbox" | "live"
const FLINKS_MODE = (process.env.FLINKS_MODE || "mock").toLowerCase();

// Toolbox/Sandbox & Live base URLs
const FLINKS_BASE_URL = process.env.FLINKS_BASE_URL || "";           // e.g. https://toolbox-api.private.fin.ag
const FLINKS_CONNECT_URL = process.env.FLINKS_CONNECT_URL || "";     // e.g. https://toolbox-iframe.private.fin.ag/v2
const FLINKS_REDIRECT_URI = process.env.FLINKS_REDIRECT_URI || "budgeteer://flinks/callback";

// Legacy OAuth/session (for live /connect/token flows)
const FLINKS_CLIENT_ID = process.env.FLINKS_CLIENT_ID || "";
const FLINKS_CLIENT_SECRET = process.env.FLINKS_CLIENT_SECRET || "";

// Toolbox/Sandbox headers
const FLINKS_X_API_KEY = process.env.FLINKS_X_API_KEY || "";
const FLINKS_BEARER = process.env.FLINKS_BEARER || "";
const FLINKS_CUSTOMER_ID = process.env.FLINKS_CUSTOMER_ID || "";
const FLINKS_AUTH_KEY = process.env.FLINKS_AUTH_KEY || ""; // not required here, but kept for future

function ensureSandbox(res: express.Response, op: string) {
  if (FLINKS_MODE !== "sandbox") {
    res.status(400).json({ error: `${op}: FLINKS_MODE must be 'sandbox'` });
    return false;
  }
  if (!FLINKS_BASE_URL || !FLINKS_CONNECT_URL || !FLINKS_X_API_KEY || !FLINKS_BEARER || !FLINKS_CUSTOMER_ID) {
    res.status(500).json({ error: "Sandbox variables missing (BASE_URL/CONNECT_URL/x-api-key/bearer/customerId)" });
    return false;
  }
  return true;
}

function ensureLive(res: express.Response, op: string) {
  if (FLINKS_MODE !== "live") {
    res.status(400).json({ error: `${op}: FLINKS_MODE must be 'live'` });
    return false;
  }
  if (!FLINKS_BASE_URL || !FLINKS_CLIENT_ID || !FLINKS_CLIENT_SECRET) {
    res.status(500).json({ error: "Live variables missing (BASE_URL/client id/secret)" });
    return false;
  }
  return true;
}

// Generic fetch with Flinks headers (works for sandbox; for live you may add different auth later)
async function flinksFetch(path: string, init?: RequestInit) {
  const url = `${FLINKS_BASE_URL}${path}`;
  const defaultHeaders: Record<string, string> = { "Content-Type": "application/json" };

  // Toolbox/Sandbox auth headers
  if (FLINKS_X_API_KEY) defaultHeaders["x-api-key"] = FLINKS_X_API_KEY;
  if (FLINKS_BEARER) defaultHeaders["Authorization"] = `Bearer ${FLINKS_BEARER}`;
  if (FLINKS_CUSTOMER_ID) {
    defaultHeaders["customerid"] = FLINKS_CUSTOMER_ID;
    defaultHeaders["x-customer-id"] = FLINKS_CUSTOMER_ID;
  }

  const headers = { ...defaultHeaders, ...(init?.headers as any) };
  const r = await fetch(url, { ...init, headers } as any);
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    throw new Error(`Flinks ${path} failed ${r.status}: ${txt}`);
  }
  return r.json();
}

/* -------------------------------- Express -------------------------------- */
const app = express();
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "1mb" }));

if (!process.env.OPENAI_API_KEY) {
  console.warn("[boot] OPENAI_API_KEY is not set; /v1/ai routes may return 500s.");
}

app.get("/health", (_req, res) =>
  res.json({ ok: true, env: { flinksMode: FLINKS_MODE, aiEnabled: !!process.env.OPENAI_API_KEY } })
);

/* --------------------------- Auth middleware ----------------------------- */
type AuthedReq = express.Request & { user?: admin.auth.DecodedIdToken };
async function requireAuth(req: AuthedReq, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (e) {
    console.error("verifyIdToken error:", e);
    res.status(401).json({ error: "Invalid token" });
  }
}

/* ---------------------------- Helpers: rules ----------------------------- */
function safeLower(s?: string | null) { return (s ?? "").toString().toLowerCase(); }

function matchWithRule(text: string, rule: { pattern: string; isRegex: boolean }) {
  if (!rule.pattern) return false;
  if (rule.isRegex) {
    try {
      const m = rule.pattern.match(/^\/(.+)\/([gimsuy]*)$/);
      if (m) return new RegExp(m[1], m[2]).test(text);
      return new RegExp(rule.pattern, "i").test(text);
    } catch {
      return safeLower(text).includes(safeLower(rule.pattern));
    }
  }
  return safeLower(text).includes(safeLower(rule.pattern));
}

async function chooseCategoryForTx(
  userId: string,
  description: string,
  amount: number,
  providerCategory?: string | null
): Promise<string> {
  if (amount > 0) return "Income";
  const rules = await prisma.userCategoryRule.findMany({ where: { userId }, orderBy: { createdAt: "asc" } });
  for (const r of rules) {
    if (matchWithRule(description, { pattern: r.pattern, isRegex: r.isRegex })) {
      return r.category || "Uncategorized";
    }
  }
  return providerCategory?.trim() || "Uncategorized";
}

/* ------------------------------- Users ----------------------------------- */
app.post("/v1/auth/sync", requireAuth, async (req: AuthedReq, res) => {
  const email = req.user?.email;
  const firebaseUid = req.user?.uid!;
  if (!email) return res.status(400).json({ error: "Email required on token" });

  const user = await prisma.user.upsert({
    where: { firebaseUid },
    update: { email },
    create: { email, firebaseUid, profile: { create: {} } },
    include: { profile: true },
  });

  res.json({ user });
});

app.get("/v1/users/me", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid }, include: { profile: true } });
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user });
});

/* ------------------------------ Accounts --------------------------------- */
app.get("/v1/accounts", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user) return res.status(404).json({ error: "User not found" });

  const accounts = await prisma.account.findMany({
    where: { userId: user.id },
    orderBy: { createdAt: "asc" },
    select: { id: true, externalId: true, name: true, nickname: true, type: true, mask: true, currency: true, balance: true },
  });

  res.json({ accounts });
});

app.patch("/v1/accounts/:id", requireAuth, async (req: AuthedReq, res) => {
  try {
    const accountId = String(req.params.id);
    const nickname = (req.body?.nickname ?? "").toString().trim();
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const account = await prisma.account.findFirst({ where: { id: accountId, userId: user.id } });
    if (!account) return res.status(404).json({ error: "Account not found" });

    const updated = await prisma.account.update({
      where: { id: account.id },
      data: { nickname: nickname || null },
      select: { id: true, externalId: true, name: true, nickname: true, type: true, mask: true, currency: true, balance: true },
    });

    res.json({ account: updated });
  } catch (e: any) {
    console.error("PATCH /v1/accounts/:id error", e);
    res.status(500).json({ error: e?.message ?? "server error" });
  }
});

/* ---------------------------- Category Rules ----------------------------- */
app.get("/v1/category-rules", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user) return res.status(404).json({ error: "User not found" });

  const rules = await prisma.userCategoryRule.findMany({ where: { userId: user.id }, orderBy: [{ createdAt: "asc" }] });
  res.json({ rules });
});

/* ---------------------------- Transactions ------------------------------- */
app.patch("/v1/transactions/:id/category", requireAuth, async (req: AuthedReq, res) => {
  try {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const txId = String(req.params.id);
    const category = String((req.body?.category ?? "")).trim();
    if (!category) return res.status(400).json({ error: "category is required" });

    const tx = await prisma.transaction.findFirst({ where: { id: txId, userId: user.id } });
    if (!tx) return res.status(404).json({ error: "Transaction not found" });

    const updated = await prisma.transaction.update({
      where: { id: tx.id },
      data: { category },
      select: { id: true, date: true, description: true, amount: true, category: true },
    });

    res.json({ transaction: updated });
  } catch (e: any) {
    console.error("PATCH /v1/transactions/:id/category error", e);
    res.status(500).json({ error: e?.message ?? "server error" });
  }
});

app.post("/v1/category-rules", requireAuth, async (req: AuthedReq, res) => {
  try {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const pattern = String((req.body?.pattern ?? "")).trim();
    const category = String((req.body?.category ?? "")).trim();
    const isRegex = !!req.body?.isRegex;
    const applyToExisting = !!req.body?.applyToExisting;

    if (!pattern) return res.status(400).json({ error: "pattern is required" });
    if (!category) return res.status(400).json({ error: "category is required" });

    if (isRegex) {
      try { new RegExp(pattern, "i"); } catch { return res.status(400).json({ error: "invalid regex pattern" }); }
    }

    const rule = await prisma.userCategoryRule.create({ data: { userId: user.id, pattern, isRegex, category } });

    if (!applyToExisting) return res.json({ rule, updatedCount: 0 });
    res.status(202).json({ rule, queued: true });

    queueMicrotask(async () => {
      try {
        if (!isRegex) {
          const result = await prisma.transaction.updateMany({
            where: { userId: user.id, description: { contains: pattern, mode: "insensitive" } },
            data: { category },
          });
          console.log(`[rules] non-regex applied -> ${result.count} rows`);
        } else {
          const rows = await prisma.transaction.findMany({ where: { userId: user.id }, select: { id: true, description: true } });
          const re = new RegExp(pattern, "i");
          const ids = rows.filter(r => re.test(String(r.description || ""))).map(r => r.id);
          if (ids.length) {
            const result = await prisma.transaction.updateMany({ where: { id: { in: ids }, userId: user.id }, data: { category } });
            console.log(`[rules] regex applied -> ${result.count} rows`);
          } else {
            console.log("[rules] regex matched 0 rows");
          }
        }
      } catch (e) {
        console.error("Background rule apply failed:", e);
      }
    });
  } catch (e: any) {
    console.error("POST /v1/category-rules error", e);
    res.status(500).json({ error: e?.message ?? "server error" });
  }
});

app.get("/v1/transactions", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user) return res.status(404).json({ error: "User not found" });

  const from = req.query.from ? new Date(String(req.query.from)) : undefined;
  const to = req.query.to ? new Date(String(req.query.to)) : undefined;

  const txs = await prisma.transaction.findMany({
    where: {
      userId: user.id,
      ...(from || to ? { date: { ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) } } : {}),
    },
    orderBy: { date: "desc" },
    select: {
      id: true,
      date: true,
      description: true,
      amount: true,
      category: true,
      account: { select: { id: true, externalId: true, name: true, nickname: true, type: true, mask: true } },
    },
  });

  res.json({ transactions: txs });
});

app.patch("/v1/transactions/:id", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user) return res.status(404).json({ error: "User not found" });

  const id = String(req.params.id);
  const category = (req.body?.category ?? "").toString().trim();
  if (!category) return res.status(400).json({ error: "category is required" });

  const tx = await prisma.transaction.findFirst({ where: { id, userId: user.id } });
  if (!tx) return res.status(404).json({ error: "Transaction not found" });

  const updated = await prisma.transaction.update({ where: { id }, data: { category }, select: { id: true, category: true } });
  res.json({ transaction: updated });
});

app.post("/v1/transactions/reclassify", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user) return res.status(404).json({ error: "User not found" });

  const from = req.body?.from ? new Date(String(req.body.from)) : undefined;
  const to = req.body?.to ? new Date(String(req.body.to)) : undefined;

  const txs = await prisma.transaction.findMany({
    where: {
      userId: user.id,
      ...(from || to ? { date: { ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) } } : {}),
    },
    select: { id: true, description: true, amount: true, category: true },
  });

  let updatedCount = 0;
  for (const t of txs) {
    const newCat = await chooseCategoryForTx(user.id, t.description, Number(t.amount), t.category);
    if (newCat !== t.category) {
      await prisma.transaction.update({ where: { id: t.id }, data: { category: newCat } });
      updatedCount++;
    }
  }
  res.json({ ok: true, updated: updatedCount });
});

/* --------------------------- Flinks: Connect ----------------------------- */
app.post("/v1/aggregations/flinks/init", requireAuth, async (_req, res) => {
  try {
    if (FLINKS_MODE === "mock") {
      return res.json({ connectUrl: "mock://connect", sessionId: "mock-session" });
    }
    if (FLINKS_MODE === "sandbox") {
      if (!ensureSandbox(res, "init")) return;
      const params = new URLSearchParams({ demo: "true", redirectUrl: FLINKS_REDIRECT_URI });
      const connectUrl = `${FLINKS_CONNECT_URL}/?${params.toString()}`;
      return res.json({ connectUrl });
    }
    // live
    if (!ensureLive(res, "init")) return;
    const params = new URLSearchParams({ redirectUrl: FLINKS_REDIRECT_URI });
    const connectUrl = `${FLINKS_CONNECT_URL}/?${params.toString()}`;
    return res.json({ connectUrl });
  } catch (e: any) {
    console.error("flinks init error", e);
    res.status(500).json({ error: e.message });
  }
});

/* ---------------------- Flinks: Exchange / Ingest ------------------------ */
app.post("/v1/aggregations/flinks/exchange", requireAuth, async (req: AuthedReq, res) => {
  const firebaseUid = req.user?.uid!;
  const user = await prisma.user.findUnique({ where: { firebaseUid } });
  if (!user) return res.status(404).json({ error: "User not found" });

  try {
    // MOCK: seed deterministic data
    if (FLINKS_MODE === "mock") {
      await seedMockDataForUser(user.id);
      return res.json({ ok: true, mode: "mock" });
    }

    // SANDBOX: direct ingest via Toolbox APIs (headers carry auth)
    if (FLINKS_MODE === "sandbox") {
      if (!ensureSandbox(res, "exchange")) return;

      const conn = await upsertConnection(user.id, "flinks-sandbox", "sandbox-token");

      // Accounts (Toolbox paths may vary; v2 is commonly available)
      const accountsResp = await flinksFetch(`/v2/accounts`, { method: "GET" });
      const accounts = Array.isArray((accountsResp as any).accounts)
        ? (accountsResp as any).accounts
        : (accountsResp as any).data ?? (accountsResp as any) ?? [];

      for (const a of accounts) {
        await upsertAccount(user.id, conn.id, {
          externalId: String(a.id || a.accountId || a.AccountId),
          name: a.name || a.displayName || a.AccountName || "Account",
          type: a.type || a.accountType || a.AccountType || "account",
          mask: a.mask || a.Last4 || null,
          currency: a.currency || a.Currency || "CAD",
          balance: Number(a.balance ?? a.CurrentBalance ?? 0),
        });
      }

      // Build map for account ids
      const accs = await prisma.account.findMany({ where: { userId: user.id }, select: { id: true, externalId: true } });
      const idByExt: Record<string, string> = {};
      for (const a of accs) idByExt[String(a.externalId)] = a.id;

      // Transactions
      const txResp = await flinksFetch(`/v2/transactions`, { method: "GET" });
      const txs = Array.isArray((txResp as any).transactions)
        ? (txResp as any).transactions
        : (txResp as any).data ?? (txResp as any) ?? [];

      let created = 0;
      for (const t of txs) {
        const acctExternalId = String(t.accountId || t.AccountId || t.account?.id || "");
        const accountId = idByExt[acctExternalId];
        if (!accountId) continue;

        const amount = Number(t.amount ?? t.Amount ?? 0);
        const desc = String(t.description || t.Memo || t.merchant || "Transaction");
        const providerCategory = t.category || t.Category || t.enrichedCategory || null;

        const chosenCategory = await chooseCategoryForTx(user.id, desc, amount, providerCategory);

        await upsertTransaction(user.id, accountId, {
          externalId: String(t.id || t.transactionId || t.TransactionId),
          date: new Date(t.date || t.postedDate || t.TransactionDate),
          description: desc,
          amount,
          category: chosenCategory,
          raw: t,
        });
        created++;
      }

      return res.json({ ok: true, accountsImported: accounts.length || 0, transactionsImported: created });
    }

    // LIVE: OAuth/session token → accounts + transactions
    if (!ensureLive(res, "exchange")) return;
    const { loginId, sessionId, code } = (req.body || {}) as any;

    const tokenResp = await flinksFetch("/connect/token", {
      method: "POST",
      body: JSON.stringify({
        client_id: FLINKS_CLIENT_ID,
        client_secret: FLINKS_CLIENT_SECRET,
        grant_type: code ? "authorization_code" : "session",
        code,
        session_id: sessionId || loginId,
      }),
    });
    const accessToken = (tokenResp as any).access_token || (tokenResp as any).token;

    const conn = await upsertConnection(user.id, sessionId || loginId || "flinks", accessToken);

    const accountsResp = await flinksFetch("/accounts", {
      method: "POST",
      body: JSON.stringify({ access_token: accessToken }),
    });
    const accounts = (accountsResp as any).accounts || accountsResp || [];
    for (const a of accounts) {
      await upsertAccount(user.id, conn.id, {
        externalId: a.id || a.accountId || a.AccountId,
        name: a.name || a.displayName || a.AccountName || "Account",
        type: a.type || a.AccountType || "account",
        mask: a.mask || a.Last4 || null,
        currency: a.currency || a.Currency || "CAD",
        balance: Number(a.balance ?? a.CurrentBalance ?? 0),
      });
    }

    const txResp = await flinksFetch("/transactions", {
      method: "POST",
      body: JSON.stringify({ access_token: accessToken }),
    });
    const txs = (txResp as any).transactions || txResp || [];

    for (const t of txs) {
      const acctExternalId = t.accountId || t.AccountId;
      const account = await prisma.account.findFirst({ where: { userId: user.id, externalId: String(acctExternalId) } });
      if (!account) continue;

      const amount = Number(t.amount ?? t.Amount ?? 0);
      const desc = t.description || t.Memo || "Transaction";
      const chosenCategory = await chooseCategoryForTx(user.id, desc, amount, t.category || t.Category);

      await upsertTransaction(user.id, account.id, {
        externalId: t.id || t.transactionId || t.TransactionId,
        date: new Date(t.date || t.TransactionDate),
        description: desc,
        amount,
        category: chosenCategory,
        raw: t,
      });
    }

    res.json({ ok: true });
  } catch (e: any) {
    console.error("flinks exchange error", e);
    res.status(500).json({ error: e.message });
  }
});

/* ------------------------------- Helpers --------------------------------- */
async function upsertConnection(userId: string, externalId: string, accessToken: string) {
  return prisma.institutionConnection.upsert({
    where: { userId_externalId: { userId, externalId } },
    update: { accessToken },
    create: { userId, provider: "flinks", externalId, accessToken },
  });
}

async function upsertAccount(
  userId: string,
  connectionId: string,
  data: { externalId: string; name: string; type: string; mask: string | null; currency: string; balance: number }
) {
  return prisma.account.upsert({
    where: { userId_externalId: { userId, externalId: data.externalId } },
    update: { connectionId, name: data.name, type: data.type, mask: data.mask, currency: data.currency, balance: data.balance },
    create: {
      userId, connectionId, provider: "flinks",
      externalId: data.externalId, name: data.name, type: data.type, mask: data.mask, currency: data.currency, balance: data.balance, nickname: null,
    },
  });
}

async function upsertTransaction(
  userId: string,
  accountId: string,
  data: { externalId: string; date: Date; description: string; amount: number; category: string; raw: any }
) {
  return prisma.transaction.upsert({
    where: { userId_externalId: { userId, externalId: data.externalId } },
    update: { accountId, date: data.date, description: data.description, amount: new Prisma.Decimal(data.amount), category: data.category, raw: data.raw as any },
    create: {
      userId, accountId, provider: "flinks",
      externalId: data.externalId, date: data.date, description: data.description, amount: new Prisma.Decimal(data.amount), category: data.category, raw: data.raw as any,
    },
  });
}

/* ------------------------------- Mock data ------------------------------- */
// (unchanged) — mock accounts & transactions omitted here for brevity; keep your originals
const MOCK_ACCOUNTS = [
  { externalId: "acc_chk_1234", name: "Chequing", type: "depository", mask: "1234", currency: "CAD", balance: 2150.33, nickname: null, provider: "mock" },
  { externalId: "acc_cc_9876", name: "Credit Card", type: "credit", mask: "9876", currency: "CAD", balance: -438.71, nickname: null, provider: "mock" },
];
// ... and your MOCK_TRANSACTIONS array from your current file (unchanged)
// --- Mock placeholders (not used in sandbox/live, but required for TS) ---
const MOCK_ACCOUNTS: any[] = [];
const MOCK_TRANSACTIONS: any[] = [];

async function seedMockDataForUser(userId: string) {
  const conn = await upsertConnection(userId, "mock-connection", "mock-token");
  for (const a of MOCK_ACCOUNTS) {
    await upsertAccount(userId, conn.id, { externalId: a.externalId, name: a.name, type: a.type, mask: a.mask, currency: a.currency, balance: a.balance });
  }
  const accs = await prisma.account.findMany({ where: { userId }, select: { id: true, externalId: true } });
  const idByExt: Record<string, string> = {}; for (const a of accs) idByExt[String(a.externalId)] = a.id;
  for (const t of MOCK_TRANSACTIONS as any[]) {
    const accId = idByExt[t.accountExternalId]; if (!accId) continue;
    const amount = Number(t.amount);
    const chosenCategory = await chooseCategoryForTx(userId, t.description, amount, t.category);
    await upsertTransaction(userId, accId, { externalId: t.externalId, date: new Date(t.date), description: t.description, amount, category: chosenCategory, raw: t });
  }
}

/* --------------------------- Dev helper (mock) --------------------------- */
if (FLINKS_MODE === "mock") {
  app.post("/v1/dev/reset", requireAuth, async (req: AuthedReq, res) => {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    await prisma.$transaction([
      prisma.transaction.deleteMany({ where: { userId: user.id } }),
      prisma.account.deleteMany({ where: { userId: user.id } }),
      prisma.institutionConnection.deleteMany({ where: { userId: user.id } }),
      prisma.userCategoryRule.deleteMany({ where: { userId: user.id } }),
    ]);

    res.json({ ok: true, cleared: true });
  });
}

/* ------------------------------ AI endpoints ----------------------------- */
app.use("/v1/ai", requireAuth, aiRouter);

/* --------------------------- Errors & Boot ------------------------------- */
app.use((err: any, _req: any, res: any, _next: any) => {
  console.error("EXPRESS ERROR:", err);
  res.status(500).json({ error: err?.message ?? "server error" });
});

process.on("SIGTERM", async () => { try { await prisma.$disconnect(); } finally { process.exit(0); } });
process.on("SIGINT", async () => { try { await prisma.$disconnect(); } finally { process.exit(0); } });

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`API listening on :${port}`));
