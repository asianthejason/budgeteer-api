// budgeteer-api/src/index.ts
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import admin from "firebase-admin";
import { PrismaClient, Prisma } from "@prisma/client";

const prisma = new PrismaClient();

/* ----------------------------- Firebase Admin ---------------------------- */
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

/* -------------------------------- Flinks -------------------------------- */
const FLINKS_MODE = (process.env.FLINKS_MODE || "mock").toLowerCase();
const FLINKS_BASE_URL = process.env.FLINKS_BASE_URL || "";
const FLINKS_CONNECT_URL = process.env.FLINKS_CONNECT_URL || "";
const FLINKS_CLIENT_ID = process.env.FLINKS_CLIENT_ID || "";
const FLINKS_CLIENT_SECRET = process.env.FLINKS_CLIENT_SECRET || "";
const FLINKS_CUSTOMER_ID = process.env.FLINKS_CUSTOMER_ID || "";
const FLINKS_REDIRECT_URI =
  process.env.FLINKS_REDIRECT_URI || "budgeteer://flinks/callback";

function ensureLive(res: express.Response, op: string) {
  if (FLINKS_MODE !== "live") {
    res.status(400).json({ error: `${op}: FLINKS_MODE must be 'live'` });
    return false;
  }
  if (!FLINKS_BASE_URL || !FLINKS_CLIENT_ID || !FLINKS_CLIENT_SECRET) {
    res.status(500).json({ error: "Flinks env vars missing" });
    return false;
  }
  return true;
}

async function flinksFetch(path: string, init?: RequestInit) {
  const url = `${FLINKS_BASE_URL}${path}`;
  const headers = { "Content-Type": "application/json", ...(init?.headers || {}) };
  const r = await fetch(url, { ...init, headers });
  if (!r.ok) throw new Error(`Flinks ${path} failed ${r.status}: ${await r.text()}`);
  return r.json();
}

/* -------------------------------- Express -------------------------------- */
const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.get("/health", (_req, res) => res.json({ ok: true }));

/* --------------------------- Auth middleware ----------------------------- */
async function requireAuth(
  req: express.Request & { user?: admin.auth.DecodedIdToken },
  res: express.Response,
  next: express.NextFunction
) {
  const authHeader = req.headers.authorization || "";
  const token =
    authHeader.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
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

/* ------------------------------- Users ----------------------------------- */
app.post(
  "/v1/auth/sync",
  requireAuth,
  async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
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
  }
);

app.get(
  "/v1/users/me",
  requireAuth,
  async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({
      where: { firebaseUid },
      include: { profile: true },
    });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user });
  }
);

/* ------------------------------ Accounts --------------------------------- */
app.get(
  "/v1/accounts",
  requireAuth,
  async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const accounts = await prisma.account.findMany({
      where: { userId: user.id },
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        externalId: true,
        name: true,
        nickname: true,
        type: true,
        mask: true,
        currency: true,
        balance: true,
      },
    });

    res.json({ accounts });
  }
);

app.patch(
  "/v1/accounts/:id",
  requireAuth,
  async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
    try {
      const accountId = String(req.params.id);
      const nickname = (req.body?.nickname ?? "").toString().trim();

      const firebaseUid = req.user?.uid!;
      const user = await prisma.user.findUnique({ where: { firebaseUid } });
      if (!user) return res.status(404).json({ error: "User not found" });

      const account = await prisma.account.findFirst({
        where: { id: accountId, userId: user.id },
      });
      if (!account) return res.status(404).json({ error: "Account not found" });

      const updated = await prisma.account.update({
        where: { id: account.id },
        data: { nickname: nickname || null },
        select: {
          id: true,
          externalId: true,
          name: true,
          nickname: true,
          type: true,
          mask: true,
          currency: true,
          balance: true,
        },
      });

      res.json({ account: updated });
    } catch (e: any) {
      console.error("PATCH /v1/accounts/:id error", e);
      res.status(500).json({ error: e?.message ?? "server error" });
    }
  }
);

/* ---------------------------- Transactions ------------------------------- */
app.get(
  "/v1/transactions",
  requireAuth,
  async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const from = req.query.from ? new Date(String(req.query.from)) : undefined;
    const to = req.query.to ? new Date(String(req.query.to)) : undefined;

    const txs = await prisma.transaction.findMany({
      where: {
        userId: user.id,
        ...(from || to
          ? {
              date: {
                ...(from ? { gte: from } : {}),
                ...(to ? { lt: to } : {}),
              },
            }
          : {}),
      },
      orderBy: { date: "desc" },
      select: {
        id: true,
        date: true,
        description: true,
        amount: true,
        category: true,
        account: {
          select: {
            id: true,
            externalId: true,
            name: true,
            nickname: true,
            type: true,
            mask: true,
          },
        },
      },
    });

    res.json({ transactions: txs });
  }
);

/* --------------------------- Flinks: Connect ----------------------------- */
app.post(
  "/v1/aggregations/flinks/init",
  requireAuth,
  async (_req, res) => {
    if (FLINKS_MODE === "mock") {
      return res.json({ connectUrl: "mock://connect", sessionId: "mock-session" });
    }

    if (!ensureLive(res, "init")) return;
    try {
      const params = new URLSearchParams({ redirectUrl: FLINKS_REDIRECT_URI });
      const connectUrl = `${FLINKS_CONNECT_URL}/?${params.toString()}`;
      res.json({ connectUrl });
    } catch (e: any) {
      console.error("flinks init error", e);
      res.status(500).json({ error: e.message });
    }
  }
);

app.post(
  "/v1/aggregations/flinks/exchange",
  requireAuth,
  async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
    const firebaseUid = req.user?.uid!;
    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    // MOCK: seed stable data (idempotent)
    if (FLINKS_MODE === "mock") {
      await seedMockDataForUser(user.id);
      return res.json({ ok: true, mode: "mock" });
    }

    if (!ensureLive(res, "exchange")) return;

    const { loginId, sessionId, code } = (req.body || {}) as any;
    try {
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
        const account = await prisma.account.findFirst({
          where: { userId: user.id, externalId: String(acctExternalId) },
        });
        if (!account) continue;

        await upsertTransaction(user.id, account.id, {
          externalId: t.id || t.transactionId || t.TransactionId,
          date: new Date(t.date || t.TransactionDate),
          description: t.description || t.Memo || "Transaction",
          amount: Number(t.amount ?? t.Amount ?? 0),
          category: t.category || t.Category || "Uncategorized",
          raw: t,
        });
      }

      res.json({ ok: true });
    } catch (e: any) {
      console.error("flinks exchange error", e);
      res.status(500).json({ error: e.message });
    }
  }
);

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
  data: {
    externalId: string;
    name: string;
    type: string;
    mask: string | null;
    currency: string;
    balance: number;
  }
) {
  // Do NOT touch nickname on updates
  return prisma.account.upsert({
    where: { userId_externalId: { userId, externalId: data.externalId } },
    update: {
      connectionId,
      name: data.name,
      type: data.type,
      mask: data.mask,
      currency: data.currency,
      balance: data.balance,
    },
    create: {
      userId,
      connectionId,
      provider: "flinks",
      externalId: data.externalId,
      name: data.name,
      type: data.type,
      mask: data.mask,
      currency: data.currency,
      balance: data.balance,
      nickname: null,
    },
  });
}

async function upsertTransaction(
  userId: string,
  accountId: string,
  data: {
    externalId: string;
    date: Date;
    description: string;
    amount: number;
    category: string;
    raw: any;
  }
) {
  return prisma.transaction.upsert({
    where: { userId_externalId: { userId, externalId: data.externalId } },
    update: {
      accountId,
      date: data.date,
      description: data.description,
      amount: new Prisma.Decimal(data.amount),
      category: data.category,
      raw: data.raw as any,
    },
    create: {
      userId,
      accountId,
      provider: "flinks",
      externalId: data.externalId,
      date: data.date,
      description: data.description,
      amount: new Prisma.Decimal(data.amount),
      category: data.category,
      raw: data.raw as any,
    },
  });
}

/* ------------------------------- Mock data ------------------------------- */
const MOCK_ACCOUNTS = [
  {
    externalId: "acc_chk_1234",
    name: "Chequing",
    type: "depository",
    mask: "1234",
    currency: "CAD",
    balance: 2150.33,
    nickname: null,
    provider: "mock",
  },
  {
    externalId: "acc_cc_9876",
    name: "Credit Card",
    type: "credit",
    mask: "9876",
    currency: "CAD",
    balance: -438.71,
    nickname: null,
    provider: "mock",
  },
];

// Aug & Sep 2025 mock transactions
const MOCK_TRANSACTIONS = [
  // ===== September 2025 =====
  { externalId: "2025-09_inc_1", accountExternalId: "acc_chk_1234", date: "2025-09-17", description: "Payroll Deposit", amount: 2500.0, category: "Income", provider: "mock" },

  { externalId: "2025-09_groc_1", accountExternalId: "acc_chk_1234", date: "2025-09-11", description: "Safeway Groceries", amount: -82.45, category: "Groceries", provider: "mock" },
  { externalId: "2025-09_groc_2", accountExternalId: "acc_chk_1234", date: "2025-09-20", description: "Costco", amount: -145.1, category: "Groceries", provider: "mock" },

  { externalId: "2025-09_sub_1", accountExternalId: "acc_chk_1234", date: "2025-09-14", description: "Spotify", amount: -10.99, category: "Subscriptions", provider: "mock" },
  { externalId: "2025-09_sub_2", accountExternalId: "acc_chk_1234", date: "2025-09-01", description: "Netflix", amount: -15.49, category: "Subscriptions", provider: "mock" },

  { externalId: "2025-09_trans_1", accountExternalId: "acc_cc_9876", date: "2025-09-15", description: "Gas Station", amount: -56.2, category: "Transport", provider: "mock" },
  { externalId: "2025-09_trans_2", accountExternalId: "acc_cc_9876", date: "2025-09-05", description: "Uber", amount: -18.75, category: "Transport", provider: "mock" },

  { externalId: "2025-09_dine_1", accountExternalId: "acc_cc_9876", date: "2025-09-07", description: "Chipotle", amount: -13.5, category: "Dining", provider: "mock" },
  { externalId: "2025-09_dine_2", accountExternalId: "acc_cc_9876", date: "2025-09-22", description: "Starbucks", amount: -5.25, category: "Dining", provider: "mock" },

  { externalId: "2025-09_util_1", accountExternalId: "acc_chk_1234", date: "2025-09-10", description: "Electricity", amount: -64.8, category: "Utilities", provider: "mock" },
  { externalId: "2025-09_util_2", accountExternalId: "acc_chk_1234", date: "2025-09-10", description: "Water", amount: -31.4, category: "Utilities", provider: "mock" },

  { externalId: "2025-09_shop_1", accountExternalId: "acc_cc_9876", date: "2025-09-18", description: "Amazon", amount: -42.99, category: "Shopping", provider: "mock" },
  { externalId: "2025-09_shop_2", accountExternalId: "acc_cc_9876", date: "2025-09-23", description: "Apple Store", amount: -19.99, category: "Shopping", provider: "mock" },

  { externalId: "2025-09_ent_1", accountExternalId: "acc_cc_9876", date: "2025-09-09", description: "Movie Tickets", amount: -28.0, category: "Entertainment", provider: "mock" },
  { externalId: "2025-09_ent_2", accountExternalId: "acc_cc_9876", date: "2025-09-27", description: "Steam", amount: -12.0, category: "Entertainment", provider: "mock" },

  { externalId: "2025-09_travel_1", accountExternalId: "acc_cc_9876", date: "2025-09-03", description: "Lyft", amount: -22.1, category: "Travel", provider: "mock" },
  { externalId: "2025-09_travel_2", accountExternalId: "acc_cc_9876", date: "2025-09-24", description: "Airbnb", amount: -85.0, category: "Travel", provider: "mock" },

  { externalId: "2025-09_health_1", accountExternalId: "acc_chk_1234", date: "2025-09-11", description: "Pharmacy", amount: -14.2, category: "Health", provider: "mock" },
  { externalId: "2025-09_health_2", accountExternalId: "acc_chk_1234", date: "2025-09-19", description: "Dentist", amount: -60.0, category: "Health", provider: "mock" },

  // ===== August 2025 =====
  { externalId: "2025-08_inc_1", accountExternalId: "acc_chk_1234", date: "2025-08-15", description: "Payroll Deposit", amount: 2500.0, category: "Income", provider: "mock" },

  { externalId: "2025-08_groc_1", accountExternalId: "acc_chk_1234", date: "2025-08-08", description: "Safeway", amount: -76.12, category: "Groceries", provider: "mock" },
  { externalId: "2025-08_groc_2", accountExternalId: "acc_chk_1234", date: "2025-08-21", description: "Costco", amount: -132.7, category: "Groceries", provider: "mock" },

  { externalId: "2025-08_sub_1", accountExternalId: "acc_chk_1234", date: "2025-08-14", description: "Spotify", amount: -10.99, category: "Subscriptions", provider: "mock" },
  { externalId: "2025-08_sub_2", accountExternalId: "acc_chk_1234", date: "2025-08-01", description: "Netflix", amount: -15.49, category: "Subscriptions", provider: "mock" },

  { externalId: "2025-08_trans_1", accountExternalId: "acc_cc_9876", date: "2025-08-06", description: "Gas", amount: -48.75, category: "Transport", provider: "mock" },
  { externalId: "2025-08_trans_2", accountExternalId: "acc_cc_9876", date: "2025-08-28", description: "Uber", amount: -16.2, category: "Transport", provider: "mock" },

  { externalId: "2025-08_dine_1", accountExternalId: "acc_cc_9876", date: "2025-08-05", description: "Taco Bell", amount: -9.8, category: "Dining", provider: "mock" },
  { externalId: "2025-08_dine_2", accountExternalId: "acc_cc_9876", date: "2025-08-18", description: "Starbucks", amount: -5.25, category: "Dining", provider: "mock" },

  { externalId: "2025-08_util_1", accountExternalId: "acc_chk_1234", date: "2025-08-10", description: "Electricity", amount: -61.1, category: "Utilities", provider: "mock" },
  { externalId: "2025-08_util_2", accountExternalId: "acc_chk_1234", date: "2025-08-10", description: "Water", amount: -28.9, category: "Utilities", provider: "mock" },

  { externalId: "2025-08_shop_1", accountExternalId: "acc_cc_9876", date: "2025-08-12", description: "Amazon", amount: -38.5, category: "Shopping", provider: "mock" },
  { externalId: "2025-08_shop_2", accountExternalId: "acc_cc_9876", date: "2025-08-25", description: "Target", amount: -24.0, category: "Shopping", provider: "mock" },

  { externalId: "2025-08_ent_1", accountExternalId: "acc_cc_9876", date: "2025-08-09", description: "Hulu", amount: -12.99, category: "Entertainment", provider: "mock" },
  { externalId: "2025-08_ent_2", accountExternalId: "acc_cc_9876", date: "2025-08-26", description: "Nintendo eShop", amount: -8.0, category: "Entertainment", provider: "mock" },

  { externalId: "2025-08_travel_1", accountExternalId: "acc_cc_9876", date: "2025-08-03", description: "Lyft", amount: -18.4, category: "Travel", provider: "mock" },
  { externalId: "2025-08_travel_2", accountExternalId: "acc_cc_9876", date: "2025-08-22", description: "Hotel.com", amount: -72.0, category: "Travel", provider: "mock" },

  { externalId: "2025-08_health_1", accountExternalId: "acc_chk_1234", date: "2025-08-11", description: "Pharmacy", amount: -11.6, category: "Health", provider: "mock" },
  { externalId: "2025-08_health_2", accountExternalId: "acc_chk_1234", date: "2025-08-20", description: "Clinic", amount: -45.0, category: "Health", provider: "mock" },
];

/* ----------------------- Mock seeding (idempotent) ----------------------- */
async function seedMockDataForUser(userId: string) {
  const conn = await upsertConnection(userId, "mock-connection", "mock-token");

  // upsert accounts (nickname preserved)
  for (const a of MOCK_ACCOUNTS) {
    await upsertAccount(userId, conn.id, {
      externalId: a.externalId,
      name: a.name,
      type: a.type,
      mask: a.mask,
      currency: a.currency,
      balance: a.balance,
    });
  }

  // build extId -> id map once
  const accs = await prisma.account.findMany({
    where: { userId },
    select: { id: true, externalId: true },
  });
  const idByExt: Record<string, string> = {};
  for (const a of accs) idByExt[String(a.externalId)] = a.id;

  // upsert transactions
  for (const t of MOCK_TRANSACTIONS) {
    const accId = idByExt[t.accountExternalId];
    if (!accId) continue;
    await upsertTransaction(userId, accId, {
      externalId: t.externalId,
      date: new Date(t.date),
      description: t.description,
      amount: t.amount,
      category: t.category,
      raw: t,
    });
  }
}

/* --------------------------- Dev helper (mock) --------------------------- */
if (FLINKS_MODE === "mock") {
  app.post(
    "/v1/dev/reset",
    requireAuth,
    async (req: express.Request & { user?: admin.auth.DecodedIdToken }, res) => {
      const firebaseUid = req.user?.uid!;
      const user = await prisma.user.findUnique({ where: { firebaseUid } });
      if (!user) return res.status(404).json({ error: "User not found" });

      await prisma.$transaction([
        prisma.transaction.deleteMany({ where: { userId: user.id } }),
        prisma.account.deleteMany({ where: { userId: user.id } }),
        prisma.institutionConnection.deleteMany({ where: { userId: user.id } }),
      ]);

      res.json({ ok: true, cleared: true });
    }
  );
}

/* --------------------------- Errors & Boot ------------------------------- */
app.use((err: any, _req: any, res: any, _next: any) => {
  console.error("EXPRESS ERROR:", err);
  res.status(500).json({ error: err?.message ?? "server error" });
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`API listening on :${port}`));
