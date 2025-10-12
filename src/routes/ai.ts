// budgeteer-api/src/routes/ai.ts
import { Router } from "express";
import type { Request, Response } from "express";
import OpenAI from "openai";
import { PrismaClient, Prisma } from "@prisma/client";

const router = Router();
const prisma = new PrismaClient();

type AuthedReq = Request & { user?: { uid: string; email?: string } };

// --- OpenAI client (defensive) ---
function getOpenAI() {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return null;
  return new OpenAI({ apiKey });
}
function requireOpenAI() {
  const c = getOpenAI();
  if (!c) {
    const err: any = new Error("OPENAI_API_KEY is not set on the server");
    err.status = 500;
    throw err;
  }
  return c;
}

// Health
router.get("/health", (_req: Request, res: Response) => {
  res.json({ ok: true, aiEnabled: !!process.env.OPENAI_API_KEY });
});

// ---------- Finance snapshot helpers ----------
function daysAgo(n: number) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

function round(n: number, p = 2) {
  return Math.round(n * 10 ** p) / 10 ** p;
}

type TxMini = { date: string; description: string; amount: number; category: string };
type Snapshot = {
  rangeDays: number;
  incomeTotal: number;
  spendTotal: number;
  net: number;
  byCategory: Array<{ category: string; total: number }>;
  recent: TxMini[];
};

async function buildSnapshot(userId: string, rangeDays = 60): Promise<Snapshot> {
  const since = daysAgo(rangeDays);

  const txs = await prisma.transaction.findMany({
    where: { userId, date: { gte: since } },
    orderBy: { date: "desc" },
    select: { date: true, description: true, amount: true, category: true },
  });

  let incomeTotal = 0;
  let spendTotal = 0;
  const catMap = new Map<string, number>();

  for (const t of txs) {
    const amt = Number(t.amount);
    if (amt > 0) incomeTotal += amt;
    else spendTotal += amt; // negative
    const cat = (t.category || "Uncategorized").trim();
    catMap.set(cat, (catMap.get(cat) || 0) + amt);
  }

  const byCategory = [...catMap.entries()]
    .map(([category, total]) => ({ category, total: round(total) }))
    .sort((a, b) => a.total - b.total) // biggest spend (most negative) first after we slice below
    .slice(0, 8);

  const recent: TxMini[] = txs.slice(0, 20).map((t) => ({
    date: t.date.toISOString().slice(0, 10),
    description: t.description,
    amount: round(Number(t.amount)),
    category: t.category || "Uncategorized",
  }));

  return {
    rangeDays,
    incomeTotal: round(incomeTotal),
    spendTotal: round(spendTotal), // negative
    net: round(incomeTotal + spendTotal),
    byCategory,
    recent,
  };
}

// ---------- Chat endpoint using user data ----------
router.post("/chat", async (req: AuthedReq, res: Response) => {
  try {
    const message = (req.body?.message ?? "").toString().trim();
    if (!message) return res.status(400).json({ error: "message is required" });

    // Find the app user by Firebase uid (set by your auth middleware)
    const firebaseUid = req.user?.uid;
    if (!firebaseUid) return res.status(401).json({ error: "Unauthorized" });

    const user = await prisma.user.findUnique({ where: { firebaseUid } });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Build snapshot
    const rangeDays = Math.max(7, Math.min(180, Number(req.body?.rangeDays ?? 60)));
    const snapshot = await buildSnapshot(user.id, rangeDays);

    const openai = requireOpenAI();

    const system = [
      "You are Budgeteer, a helpful personal finance assistant.",
      "Ground every answer in the user's provided finance snapshot.",
      "Prefer concrete numbers (totals, category spend, examples), then give 2-4 actionable next steps.",
      "Be concise. Use short paragraphs or bullet points. No tables unless asked.",
      "If data is missing or insufficient, say so briefly and suggest what to link or collect.",
    ].join(" ");

    // Keep the snapshot compact to control tokens
    const snapshotText =
      "USER_FINANCE_SNAPSHOT\n" + JSON.stringify(snapshot, null, 0).slice(0, 12000);

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      temperature: 0.4,
      max_tokens: 450,
      messages: [
        { role: "system", content: system },
        {
          role: "system",
          content:
            "The following JSON is the user's recent financial context for the last " +
            rangeDays +
            " days. Use it for calculations:\n" +
            "```json\n" +
            snapshotText +
            "\n```",
        },
        { role: "user", content: message },
      ],
      timeout: 20_000,
    });

    const reply =
      completion.choices?.[0]?.message?.content?.toString() ??
      "Sorry, I couldn't generate a response.";

    res.json({ reply, snapshot });
  } catch (e: any) {
    const status = e?.status || e?.response?.status || 500;
    const detail = e?.message || "AI error";
    res.status(status).json({ error: "AI error", detail });
  }
});

export default router;
