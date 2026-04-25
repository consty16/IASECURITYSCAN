import { createRequire } from "module";
const require = createRequire(import.meta.url);
const entidades = require("../entidades.json");

// 🔥 FETCH CON TIMEOUT
const fetchSafe = async (url, options = {}, timeout = 4000) => {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout")), timeout)
    )
  ]);
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método no permitido" });
  }

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL requerida" });
  if (!url.startsWith("http")) {
    return res.status(400).json({ error: "URL inválida" });
  }

  let resultados = [];
  let score = 0;
  let domain;

  try {
    domain = new URL(url).hostname.toLowerCase();
  } catch {
    return res.status(400).json({ error: "URL inválida" });
  }

  const entidad = entidades.find(
    e => domain === e.dominio || domain.endsWith("." + e.dominio)
  );

  if (entidad) {
    resultados.push(`✅ Sitio oficial: ${entidad.nombre}`);
    score -= 10;
  } else {
    resultados.push("⚠️ No coincide con entidad oficial");
    score += 20;
  }

  try {
    // 🟢 GOOGLE
    try {
      const safeRes = await fetchSafe(
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
      const safeData = await safeRes.json().catch(() => ({}));
      if (safeData.matches) {
        resultados.push("Phishing/Malware detectado (Google)");
        score += 40;
      }
    } catch {}

    // 🟡 VIRUSTOTAL
    try {
      await fetchSafe("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": process.env.VT_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ url })
      });
      resultados.push("Analizado por VirusTotal");
      score += 10;
    } catch {}

    // 🟡 WHOIS
    try {
      const whoisRes = await fetchSafe(
        `https://api.api-ninjas.com/v1/whois?domain=${domain}`,
        { headers: { "X-Api-Key": process.env.WHOIS_KEY } }
      );
      const whois = await whoisRes.json().catch(() => ({}));
      if (whois.creation_date) {
        const created = new Date(whois.creation_date);
        const ageDays = (Date.now() - created) / (1000 * 60 * 60 * 24);
        if (ageDays < 30) {
          resultados.push("Dominio muy nuevo (alto riesgo)");
          score += 25;
        }
      }
    } catch {}

    // 🟣 OTX
    try {
      const otxRes = await fetchSafe(
        `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`,
        { headers: { "X-OTX-API-KEY": process.env.OTX_KEY } }
      );
      const otxData = await otxRes.json().catch(() => ({}));
      if (otxData.pulse_info?.count > 0) {
        resultados.push("Reportado en inteligencia de amenazas (OTX)");
        score += 30;
      }
    } catch {}

    // 🔵 IP
    let ip = null;
    try {
      ip = await fetchSafe(`https://dns.google/resolve?name=${domain}`)
        .then(r => r.json().catch(() => ({})))
        .then(d => (d.Answer ? d.Answer[0].data : null));
    } catch {}

    // 🔵 ABUSE
    if (ip) {
      try {
        const abuseRes = await fetchSafe(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
          {
            headers: {
              Key: process.env.ABUSE_KEY,
              Accept: "application/json"
            }
          }
        );
        const abuseData = await abuseRes.json().catch(() => ({}));
        if (abuseData.data?.abuseConfidenceScore > 50) {
          resultados.push("IP reportada por actividad maliciosa");
          score += 25;
        }
      } catch {}
    }

    // 🟦 SHODAN
    if (ip) {
      try {
        const shodanRes = await fetchSafe(`https://internetdb.shodan.io/${ip}`);
        const shodanData = await shodanRes.json().catch(() => ({}));
        if (shodanData.ports?.length > 0) {
          resultados.push(`Puertos abiertos: ${shodanData.ports.join(", ")}`);
          score += 10;
        }
      } catch {}
    }

    // 🔴 URLSCAN
    try {
      const urlscanRes = await fetchSafe("https://urlscan.io/api/v1/scan/", {
        method: "POST",
        headers: {
          "API-Key": process.env.URLSCAN_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url, visibility: "public" })
      });
      if (urlscanRes.ok) {
        resultados.push("Analizando comportamiento (URLScan)");
        score += 10;
      }
    } catch {}

    // 🌍 GEO IP
    if (ip) {
      try {
        const geoRes = await fetchSafe(`http://ip-api.com/json/${ip}`);
        const geoData = await geoRes.json().catch(() => ({}));
        if (geoData.country) {
          resultados.push(`Servidor en: ${geoData.country}`);
        }
      } catch {}
    }

    // 🌐 DNS
    try {
      const dnsRes = await fetchSafe(`https://dns.google/resolve?name=${domain}&type=NS`);
      const dnsData = await dnsRes.json().catch(() => ({}));
      if (!dnsData.Answer) {
        resultados.push("DNS sospechoso");
        score += 15;
      }
    } catch {}

    // 🧠 HTML
    let html = "";
    try {
      const htmlRes = await fetchSafe(url);
      html = await htmlRes.text();
    } catch {
      resultados.push("No se pudo analizar HTML");
    }

    const htmlLower = html.toLowerCase();

    if (html.includes("<form") && html.match(/password/i)) {
      resultados.push("Formulario de login detectado");
      score += 25;
    }

    if (html.match(/usuario|dni|clave|password|token/i)) {
      resultados.push("Captura de credenciales");
      score += 40;
    }

    const marcas = ["banco","mercado pago","uala","paypal"];
    for (let marca of marcas) {
      if (htmlLower.includes(marca) && !entidad) {
        resultados.push(`🚨 Clon financiero de ${marca}`);
        score += 50;
      }
    }

    // 💣 HEURÍSTICAS
    if (!url.startsWith("https")) {
      resultados.push("Sitio sin HTTPS");
      score += 10;
    }

    if (/login|verify|secure|update/i.test(url)) {
      resultados.push("Patrón típico de phishing");
      score += 15;
    }

    if (url.includes("@") || url.includes("-")) {
      resultados.push("Dominio sospechoso");
      score += 10;
    }

    if (url.match(/\.(apk|exe|zip|rar)$/i)) {
      resultados.push("Descarga potencialmente peligrosa");
      score += 30;
    }

    let riesgo = "BAJO";
    if (score > 80) riesgo = "CRITICO";
    else if (score > 50) riesgo = "ALTO";
    else if (score > 20) riesgo = "MEDIO";

    res.json({ url, riesgo, score, resultados });

  } catch (error) {
    console.error("ERROR REAL:", error?.message, error?.stack);
    res.status(500).json({ error: error?.message || "Error en el análisis" });
  }
}
