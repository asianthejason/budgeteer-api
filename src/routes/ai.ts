// budgeteer-api/src/routes/ai.ts
import { Router } from "express";
import { openai } from "../ai/openai";

const router = Router();

/**
 * POST /v1/ai/chat
 * body: { message: string }
 * Returns: { reply: string }
 */
router.post("/chat", async (req, res) => {
  try {
    const { message } = req.body || {};
    if (!message || typeof message !== "string") {
      return res.status(400).json({ error: "message is required" });
    }

    // Minimal call: no tools yet. We just confirm your wiring works.
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are Budgeteer Assistant. Be concise and helpful. If asked about finances, say you need data-access enabled features that we will add next.",
        },
        { role: "user", content: message },
      ],
      temperature: 0.5,
    });

    const reply =
      completion.choices?.[0]?.message?.content?.trim() ||
      "Sorry, I couldn't generate a reply.";

    res.json({ reply });
  } catch (err: any) {
    console.error("AI /chat error:", err?.message || err);
    res.status(500).json({ error: "AI error", detail: String(err?.message || err) });
  }
});

export default router;
