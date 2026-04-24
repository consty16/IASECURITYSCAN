import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post("/api/scan", async (req, res) => {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === "MY_GEMINI_API_KEY") {
      return res.status(500).json({ error: "GEMINI_API_KEY no está configurada. Por favor, asegúrate de ingresar tu API Key en la configuración (Settings/Secrets)." });
    }

    // Initialize Gemini dynamically inside the route so it catches environment variable updates
    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

    try {
      // Heuristics to provide context
      const isHttps = url.startsWith("https://");
      const domain = url.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split("/")[0];
      const hasSuspiciousTLD = /\.(xyz|top|pw|id|icu|loan|men|stream|win|bid|online)$/i.test(domain);
      const isShortened = /bit\.ly|t\.co|goo\.gl|tinyurl\.com|ow\.ly/i.test(domain);

      const prompt = `
        Eres un experto en ciberseguridad de nivel profesional. Analiza el siguiente enlace sospechoso:
        URL: ${url}
        Contexto técnico detectado:
        - HTTPS: ${isHttps ? "Sí" : "No (Riesgoso)"}
        - Dominio: ${domain}
        - TLD Sospechoso: ${hasSuspiciousTLD ? "Sí" : "No"}
        - Acortador de URL detectado: ${isShortened ? "Sí" : "No"}

        Genera un informe detallado siguiendo estas reglas:
        1. Diagnóstico: Resumen claro de lo que es (phishing, malware, etc).
        2. Riesgos Detectados: Lista de amenazas específicas.
        3. Interpretación: Qué significa esto para el usuario.
        4. Recomendación: Acciones exactas a tomar.
        5. Score: Un número de 0 a 100 y el nivel correspondente.

        Usa un lenguaje profesional pero claro. No asegures que nada es 100% seguro.
      `;

      const result = await ai.models.generateContent({
        model: "gemini-2.0-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              diagnostico: { type: Type.STRING },
              riesgos: { 
                type: Type.ARRAY,
                items: { type: Type.STRING }
              },
              interpretacion: { type: Type.STRING },
              recomendacion: { type: Type.STRING },
              score: { type: Type.INTEGER },
              nivel: { type: Type.STRING }
            },
            required: ["diagnostico", "riesgos", "interpretacion", "recomendacion", "score", "nivel"]
          }
        }
      });
      
      const response = JSON.parse(result.text || "{}");
      
      res.json(response);
    } catch (error) {
      console.error("Analysis Error:", error);
      res.status(500).json({ error: "Ocurrió un error al analizar el enlace." });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
