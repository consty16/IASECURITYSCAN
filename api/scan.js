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

// 🚪 Puertos que SÍ son sospechosos (80 y 443 son NORMALES, no se penalizan)
const PUERTOS_SOSPECHOSOS = [22, 23, 3389, 4444, 5900, 8080, 8443, 9200, 27017];

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

  // ✅ Verificar entidad oficial financiera argentina
  const entidad = Array.isArray(entidades)
    ? entidades.find(
        e => domain === e.dominio || domain.endsWith("." + e.dominio)
      )
    : null;

  // Solo penalizar si el dominio PARECE financiero pero no está en la lista
  const pareceFinanciero = /banco|pago|pay|wallet|tarjeta|credito|fintech|uala|mercado/i.test(domain);

  if (entidad) {
    resultados.push(`✅ Sitio oficial verificado: ${entidad.nombre}`);
    score -= 10;
  } else if (pareceFinanciero) {
    resultados.push("🚨 Parece un sitio financiero pero NO está en la lista oficial");
    score += 30;
  }
  // Si no es financiero → no penalizar por no estar en la lista

  try {
    // 🟢 GOOGLE SAFE BROWSING
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
      if (safeData.matches && safeData.matches.length > 0) {
        resultados.push("🚨 Phishing/Malware detectado por Google Safe Browsing");
        score += 40;
      } else {
        resultados.push("✅ Sin amenazas en Google Safe Browsing");
      }
    } catch {
      resultados.push("⚠️ Google Safe Browsing no disponible");
    }

    // 🟡 VIRUSTOTAL — envío + lectura real del resultado
    try {
      const vtSubmit = await fetchSafe(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: {
            "x-apikey": process.env.VT_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({ url })
        }
      );
      const vtSubmitData = await vtSubmit.json().catch(() => ({}));
      const analysisId = vtSubmitData?.data?.id;

      if (analysisId) {
        await new Promise(r => setTimeout(r, 2000));
        const vtResult = await fetchSafe(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          { headers: { "x-apikey": process.env.VT_API_KEY } },
          6000
        );
        const vtData = await vtResult.json().catch(() => ({}));
        const stats = vtData?.data?.attributes?.stats;

        if (stats) {
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          if (malicious > 0 || suspicious > 0) {
            resultados.push(`🚨 VirusTotal: ${malicious} motor(es) lo marcan como malicioso`);
            score += malicious > 3 ? 40 : 20;
          } else {
            resultados.push("✅ VirusTotal: sin detecciones maliciosas");
          }
        } else {
          resultados.push("⏳ VirusTotal: análisis en proceso");
        }
      } else {
        resultados.push("⚠️ VirusTotal: no se pudo enviar la URL");
      }
    } catch {
      resultados.push("⚠️ VirusTotal no disponible");
    }

    // 🟡 WHOIS — antigüedad del dominio
    try {
      const whoisRes = await fetchSafe(
        `https://api.api-ninjas.com/v1/whois?domain=${domain}`,
        { headers: { "X-Api-Key": process.env.WHOIS_KEY } }
      );
      const whois = await whoisRes.json().catch(() => ({}));
      if (whois.creation_date) {
        const created = new Date(
          typeof whois.creation_date === "number"
            ? whois.creation_date * 1000
            : whois.creation_date
        );
        const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays < 30) {
          resultados.push(`🚨 Dominio muy nuevo: ${Math.floor(ageDays)} días de antigüedad`);
          score += 25;
        } else if (ageDays < 90) {
          resultados.push(`⚠️ Dominio reciente: ${Math.floor(ageDays)} días`);
          score += 10;
        } else {
          resultados.push(`✅ Dominio con ${Math.floor(ageDays / 365)} año(s) de antigüedad`);
        }
      } else {
        resultados.push("⚠️ WHOIS: no se encontró fecha de creación");
      }
    } catch {
      resultados.push("⚠️ WHOIS no disponible");
    }

    // 🟣 OTX AlienVault
    try {
      const otxRes = await fetchSafe(
        `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`,
        { headers: { "X-OTX-API-KEY": process.env.OTX_KEY } }
      );
      const otxData = await otxRes.json().catch(() => ({}));
      if (otxData.pulse_info?.count > 0) {
        resultados.push(`🚨 Reportado en ${otxData.pulse_info.count} alerta(s) de inteligencia (OTX)`);
        score += 30;
      } else {
        resultados.push("✅ Sin reportes en OTX AlienVault");
      }
    } catch {
      resultados.push("⚠️ OTX no disponible");
    }

    // 🔵 Resolución de IP
    let ip = null;
    try {
      const dnsIpRes = await fetchSafe(
        `https://dns.google/resolve?name=${domain}&type=A`,
        {},
        5000
      );
      const dnsIpData = await dnsIpRes.json().catch(() => ({}));
      ip = dnsIpData?.Answer?.find(r => r.type === 1)?.data || null;
      if (ip) {
        resultados.push(`🌐 IP resuelta: ${ip}`);
      } else {
        resultados.push("⚠️ No se pudo resolver la IP del dominio");
        score += 10;
      }
    } catch {
      resultados.push("⚠️ Resolución DNS fallida");
    }

    // 🔵 ABUSEIPDB
    if (ip) {
      try {
        const abuseRes = await fetchSafe(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
          {
            headers: {
              "Key": process.env.ABUSE_KEY,
              "Accept": "application/json"
            }
          }
        );
        const abuseData = await abuseRes.json().catch(() => ({}));
        const abuseScore = abuseData.data?.abuseConfidenceScore;
        if (abuseScore !== undefined) {
          if (abuseScore > 50) {
            resultados.push(`🚨 IP con ${abuseScore}% de índice de abuso (AbuseIPDB)`);
            score += 25;
          } else if (abuseScore > 10) {
            resultados.push(`⚠️ IP con actividad sospechosa leve: ${abuseScore}%`);
            score += 10;
          } else {
            resultados.push("✅ IP sin reportes de abuso");
          }
        }
      } catch {
        resultados.push("⚠️ AbuseIPDB no disponible");
      }
    }

    // 🟦 SHODAN InternetDB — solo puertos realmente sospechosos
    if (ip) {
      try {
        const shodanRes = await fetchSafe(`https://internetdb.shodan.io/${ip}`);
        const shodanData = await shodanRes.json().catch(() => ({}));

        if (shodanData.ports?.length > 0) {
          const portosRiesgosos = shodanData.ports.filter(p =>
            PUERTOS_SOSPECHOSOS.includes(p)
          );
          if (portosRiesgosos.length > 0) {
            resultados.push(`⚠️ Puertos de riesgo detectados: ${portosRiesgosos.join(", ")}`);
            score += 15;
          } else {
            resultados.push(`✅ Puertos abiertos normales (${shodanData.ports.join(", ")})`);
          }
        } else {
          resultados.push("✅ Sin puertos sospechosos (Shodan)");
        }

        if (shodanData.vulns?.length > 0) {
          resultados.push(`🚨 Vulnerabilidades conocidas: ${shodanData.vulns.join(", ")}`);
          score += 20;
        }
      } catch {
        resultados.push("⚠️ Shodan no disponible");
      }
    }

    // 🔴 URLSCAN
    try {
      const urlscanRes = await fetchSafe(
        "https://urlscan.io/api/v1/scan/",
        {
          method: "POST",
          headers: {
            "API-Key": process.env.URLSCAN_KEY,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url, visibility: "public" })
        }
      );
      const urlscanData = await urlscanRes.json().catch(() => ({}));
      if (urlscanRes.ok && urlscanData.uuid) {
        resultados.push("🔍 Análisis de comportamiento enviado a URLScan");
      } else {
        resultados.push("⚠️ URLScan: no se pudo iniciar análisis");
      }
    } catch {
      resultados.push("⚠️ URLScan no disponible");
    }

    // 🌍 GEO IP — ✅ FIX: https en lugar de http
    if (ip) {
      try {
        const geoRes = await fetchSafe(`https://ip-api.com/json/${ip}`);
        const geoData = await geoRes.json().catch(() => ({}));
        if (geoData.country) {
          resultados.push(`🌍 Servidor en: ${geoData.country} — ${geoData.city || "ciudad desconocida"}`);
          const paisesRiesgo = ["Russia", "China", "North Korea", "Iran"];
          if (paisesRiesgo.includes(geoData.country)) {
            resultados.push("⚠️ País asociado a alto riesgo cibernético");
            score += 15;
          }
        }
      } catch {
        resultados.push("⚠️ Geolocalización no disponible");
      }
    }

    // 🌐 DNS NS Records — timeout mayor para evitar falsos positivos
    try {
      const dnsRes = await fetchSafe(
        `https://dns.google/resolve?name=${domain}&type=NS`,
        {},
        6000
      );
      const dnsData = await dnsRes.json().catch(() => ({}));
      if (!dnsData.Answer || dnsData.Answer.length === 0) {
        resultados.push("⚠️ Sin registros NS encontrados — DNS sospechoso");
        score += 10;
      } else {
        resultados.push("✅ Registros DNS NS válidos");
      }
    } catch {
      // Timeout en DNS no suma score — puede ser falso positivo
      resultados.push("⚠️ Verificación DNS NS no disponible (timeout)");
    }

    // 🧠 ANÁLISIS HTML
    let html = "";
    try {
      const htmlRes = await fetchSafe(url, {}, 5000);
      html = await htmlRes.text();
    } catch {
      resultados.push("⚠️ No se pudo analizar el HTML del sitio");
    }

    if (html) {
      const htmlLower = html.toLowerCase();

      if (html.includes("<form") && /password|contraseña/i.test(html)) {
        resultados.push("⚠️ Formulario de login detectado en el HTML");
        score += 25;
      }

      if (/usuario|dni|clave|password|token/i.test(html)) {
        resultados.push("🚨 Posible captura de credenciales en el HTML");
        score += 40;
      }

      const marcas = ["mercado pago", "uala", "paypal", "bbva", "santander", "banco galicia"];
      for (const marca of marcas) {
        if (htmlLower.includes(marca) && !entidad) {
          resultados.push(`🚨 Menciona "${marca}" sin ser sitio oficial verificado`);
          score += 50;
        }
      }

      if (/window\.location|document\.location|meta.*refresh/i.test(html)) {
        resultados.push("⚠️ Redirección automática detectada en el sitio");
        score += 15;
      }
    }

    // 💣 HEURÍSTICAS DE URL
    if (!url.startsWith("https")) {
      resultados.push("⚠️ Sitio sin HTTPS — conexión no cifrada");
      score += 10;
    }

    if (/login|verify|secure|update|account|confirm/i.test(url)) {
      resultados.push("⚠️ URL con palabras clave típicas de phishing");
      score += 15;
    }

    if (url.includes("@")) {
      resultados.push("🚨 URL contiene '@' — técnica de engaño clásica");
      score += 20;
    }

    const guiones = (domain.match(/-/g) || []).length;
    if (guiones > 3) {
      resultados.push(`⚠️ Dominio con ${guiones} guiones — patrón sospechoso`);
      score += 10;
    }

    if (url.match(/\.(apk|exe|zip|rar)$/i)) {
      resultados.push("🚨 URL apunta a una descarga potencialmente peligrosa");
      score += 30;
    }

    const subdominios = domain.split(".").length - 2;
    if (subdominios > 2) {
      resultados.push(`⚠️ Exceso de subdominios (${subdominios}) — técnica de camuflaje`);
      score += 15;
    }

    // 🎯 NIVEL DE RIESGO FINAL
    score = Math.max(0, score); // nunca negativo
    let riesgo = "BAJO";
    if (score > 80) riesgo = "CRITICO";
    else if (score > 50) riesgo = "ALTO";
    else if (score > 20) riesgo = "MEDIO";

    return res.json({ url, riesgo, score, resultados });

  } catch (error) {
    console.error("ERROR REAL:", error?.message, error?.stack);
    return res.status(500).json({ error: error?.message || "Error en el análisis" });
  }
}
