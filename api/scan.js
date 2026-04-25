export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método no permitido" });
  }

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL requerida" });

  let resultados = [];
  let score = 0;
  let domain = new URL(url).hostname.toLowerCase();

  try {

    // 🟢 GOOGLE SAFE BROWSING
    try {
      const safeRes = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "scanner", clientVersion: "1.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }]
            }
          })
        }
      );

      const safeData = await safeRes.json();
      if (safeData.matches) {
        resultados.push("🚨 Phishing/Malware detectado (Google)");
        score += 70;
      }
    } catch {}

    // 🟡 VIRUSTOTAL
    try {
      await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": process.env.VT_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ url })
      });

      resultados.push("Analizado por VirusTotal");
      score += 20;
    } catch {}

    // 🧠 HTML + CLONES
    try {
      const htmlRes = await fetch(url);
      const html = await htmlRes.text();
      const htmlLower = html.toLowerCase();

      if (html.includes("<form") && html.match(/password/i)) {
        resultados.push("Formulario de login detectado");
        score += 25;
      }

      if (
        html.match(/usuario|dni|clave|password|token/i) &&
        html.match(/banco|bank|login|cuenta/i)
      ) {
        resultados.push("🚨 Robo de credenciales");
        score += 40;
      }

      const marcas = [
        "banco de la nacion","nacion","bna","banco provincia","provincia","bapro",
        "banco ciudad","ciudad","bancor","cordoba","pampa","corrientes","neuquen",
        "santiago","chubut","santacruz","tucuman",
        "banco galicia","galicia","santander","bbva","macro",
        "patagonia","hsbc","icbc","supervielle","hipotecario",
        "credicoop","comafi","cmf","columbia","valores","bst",
        "banco del sol","delsol","brubank","openbank",
        "mercado pago","mercadopago","uala","personal pay","personalpay",
        "naranja x","naranjax","lemon","lemon cash","lemoncash",
        "prex","claro pay","claropay","belo","astropay","fiwind",
        "cocos","cocos pay","cocospay","n1u",
        "modo","cuenta dni","cuentadni","bna+","bnamas",
        "reba","go galicia","go bbva","go santander",
        "google pay","googlepay","apple pay","applepay",
        "paypal","payoneer",
        "plus pagos","pluspagos","taca taca","tacataca",
        "moni","pago24"
      ];

      for (let marca of marcas) {
        if (htmlLower.includes(marca) && !domain.includes(marca)) {
          resultados.push(`🚨 Clon de ${marca}`);
          score += 50;
        }
      }

    } catch {}

    // 💣 HEURÍSTICAS
    if (!url.startsWith("https")) {
      resultados.push("Sin HTTPS");
      score += 15;
    }

    if (/login|verify|secure|update/i.test(url)) {
      resultados.push("Patrón phishing");
      score += 25;
    }

    // 🤖 GEMINI (USA TU SECRET)
    try {
      const aiRes = await fetch(
        `https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=${process.env.Gemini_api}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{
              parts: [{ text: `Analiza si esta URL es phishing: ${url}` }]
            }]
          })
        }
      );

      const aiData = await aiRes.json();
      const aiText = aiData.candidates?.[0]?.content?.parts?.[0]?.text;

      if (aiText) {
        resultados.push("🤖 IA: " + aiText);
        score += 10;
      }

    } catch {}

    // 🎯 RESULTADO
    let riesgo = "BAJO";
    if (score > 80) riesgo = "CRITICO";
    else if (score > 50) riesgo = "ALTO";
    else if (score > 20) riesgo = "MEDIO";

    res.json({ url, riesgo, score, resultados });

  } catch {
    res.status(500).json({ error: "Error en el análisis" });
  }
}
