// budgeteer-api/src/ai/openai.ts
import OpenAI from "openai";

if (!process.env.OPENAI_API_KEY) {
  console.warn("[AI] OPENAI_API_KEY is not set. /v1/ai/chat will fail until you add it.");
}

export const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});
