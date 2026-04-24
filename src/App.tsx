import React, { useState } from "react";
import { Shield, ShieldAlert, ShieldCheck, Info, Loader2, Search, ExternalLink, AlertTriangle, ChevronRight } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface ScanResult {
  diagnostico: string;
  riesgos: string[];
  interpretacion: string;
  recomendacion: string;
  score: number;
  nivel: string;
}

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) throw new Error("Error en el servidor");

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError("No se pudo completar el análisis. Intente de nuevo.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score <= 20) return "text-emerald-400 border-emerald-500/20 bg-emerald-500/5";
    if (score <= 50) return "text-yellow-400 border-yellow-500/20 bg-yellow-500/5";
    if (score <= 80) return "text-orange-400 border-orange-500/20 bg-orange-500/5";
    return "text-red-500 border-red-500/20 bg-red-500/5";
  };

  const getScoreBg = (score: number) => {
    if (score <= 20) return "bg-emerald-500";
    if (score <= 50) return "bg-yellow-500";
    if (score <= 80) return "bg-orange-500";
    return "bg-red-500";
  };

  const getShieldIcon = (score: number) => {
    if (score <= 20) return <ShieldCheck className="w-8 h-8 text-emerald-400" />;
    if (score <= 50) return <Info className="w-8 h-8 text-yellow-400" />;
    if (score <= 80) return <ShieldAlert className="w-8 h-8 text-orange-400" />;
    return <AlertTriangle className="w-8 h-8 text-red-500 animate-pulse" />;
  };

  return (
    <div className="min-h-screen bg-[#0a0a0b] text-zinc-100 font-sans selection:bg-red-500/30 selection:text-red-200">
      <div className="max-w-4xl mx-auto px-6 py-12">
        {/* Header */}
        <header className="mb-12 text-center md:text-left flex flex-col md:flex-row items-center gap-6">
          <div className="relative">
            <div className="absolute -inset-1 bg-red-500 rounded-full blur opacity-20 group-hover:opacity-100 transition duration-1000 group-hover:duration-200 animate-pulse"></div>
            <div className="relative bg-zinc-950 p-4 rounded-full border border-zinc-800">
              <Shield className="w-10 h-10 text-red-500" />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tighter text-white font-mono uppercase">
              AI Security <span className="text-red-500">Scanner</span>
            </h1>
            <p className="text-zinc-500 text-sm mt-1 max-w-md">
              Analizador profesional de enlaces basado en inteligencia artificial y patrones de fraude SOC-Grade.
            </p>
          </div>
        </header>

        {/* Search Box */}
        <div className="relative group mb-12">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-zinc-800 to-zinc-700 rounded-2xl blur opacity-20 group-focus-within:opacity-40 transition duration-300"></div>
          <form 
            onSubmit={handleScan}
            className="relative bg-zinc-900 border border-zinc-800 rounded-2xl p-2 flex items-center shadow-2xl"
          >
            <div className="flex-1 flex items-center px-4">
              <Search className="w-5 h-5 text-zinc-500 mr-3" />
              <input
                type="text"
                placeholder="Pegue aquí el enlace sospechoso para análisis técnico..."
                className="w-full bg-transparent border-none outline-none text-zinc-100 placeholder:text-zinc-600 py-3"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
            <button
              disabled={loading || !url}
              className="bg-zinc-100 hover:bg-white text-black font-semibold px-6 py-3 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center whitespace-nowrap"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin mr-2" />
                  Analizando...
                </>
              ) : (
                <>ESCANEAR URL</>
              )}
            </button>
          </form>
          {error && (
            <p className="absolute -bottom-7 left-2 text-red-400 text-xs font-medium flex items-center">
              <AlertTriangle className="w-3 h-3 mr-1" /> {error}
            </p>
          )}
        </div>

        {/* Results Area */}
        <AnimatePresence mode="wait">
          {loading && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="mt-12 space-y-4"
            >
              <div className="h-64 rounded-2xl border border-zinc-800/50 bg-zinc-900/20 flex flex-col items-center justify-center space-y-4 overflow-hidden relative">
                <div className="absolute inset-0 bg-gradient-to-t from-red-500/5 to-transparent"></div>
                <div className="relative flex space-x-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                  <div className="w-2 h-2 bg-red-500 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                  <div className="w-2 h-2 bg-red-500 rounded-full animate-bounce"></div>
                </div>
                <p className="text-zinc-500 font-mono text-xs uppercase tracking-widest animate-pulse">
                  Extrayendo metadatos y analizando reputación...
                </p>
              </div>
            </motion.div>
          )}

          {result && !loading && (
            <motion.div
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="space-y-6"
            >
              {/* Main Score Box */}
              <div className={`p-8 rounded-3xl border-2 transition-all duration-700 ${getScoreColor(result.score)}`}>
                <div className="flex flex-col md:flex-row items-center gap-8">
                  <div className="flex-1 space-y-4 text-center md:text-left">
                    <div className="flex items-center justify-center md:justify-start gap-3">
                      <span className="text-xs font-bold uppercase tracking-widest opacity-70">Resultado del Análisis</span>
                      <ChevronRight className="w-4 h-4 opacity-30" />
                      <span className="text-xs font-bold uppercase tracking-widest">{result.nivel}</span>
                    </div>
                    <div className="flex flex-col space-y-2">
                      <h2 className="text-4xl md:text-5xl font-bold tracking-tight text-white">
                        {result.score}/100
                      </h2>
                      <p className="text-lg opacity-90 font-medium">{result.diagnostico}</p>
                    </div>
                  </div>
                  <div className="flex flex-col items-center gap-3">
                    <div className="relative">
                      <div className={`absolute -inset-4 rounded-full blur-2xl opacity-20 ${getScoreBg(result.score)}`}></div>
                      <div className="relative bg-[#0a0a0b] p-6 rounded-full border border-white/5">
                        {getShieldIcon(result.score)}
                      </div>
                    </div>
                    <span className="text-[10px] font-mono opacity-50 uppercase tracking-[0.2em]">Risk Sensor</span>
                  </div>
                </div>
                
                {/* Score Bar */}
                <div className="mt-8 h-2 w-full bg-black/40 rounded-full overflow-hidden border border-white/5">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${result.score}%` }}
                    transition={{ duration: 1.5, ease: "easeOut" }}
                    className={`h-full ${getScoreBg(result.score)}`}
                  ></motion.div>
                </div>
              </div>

              {/* Details Grid */}
              <div className="grid md:grid-cols-2 gap-6">
                {/* Interpretación */}
                <div className="bg-zinc-900/50 border border-zinc-800 p-8 rounded-3xl space-y-4">
                  <div className="flex items-center gap-3 text-zinc-400">
                    <Info className="w-5 h-5" />
                    <h3 className="font-bold uppercase text-xs tracking-widest">Interpretación Técnica</h3>
                  </div>
                  <p className="text-zinc-300 leading-relaxed text-sm">
                    {result.interpretacion}
                  </p>
                </div>

                {/* Recomendación */}
                <div className="bg-zinc-900/50 border border-zinc-800 p-8 rounded-3xl space-y-4 border-l-4 border-l-cyan-500/30">
                  <div className="flex items-center gap-3 text-cyan-400">
                    <ShieldCheck className="w-5 h-5" />
                    <h3 className="font-bold uppercase text-xs tracking-widest">Recomendación Directa</h3>
                  </div>
                  <p className="text-zinc-300 leading-relaxed text-sm">
                    {result.recomendacion}
                  </p>
                </div>
              </div>

              {/* Risks List */}
              <div className="bg-zinc-900 border border-zinc-800 p-8 rounded-3xl space-y-6">
                <div className="flex items-center gap-3 text-red-500/80">
                  <AlertTriangle className="w-5 h-5" />
                  <h3 className="font-bold uppercase text-xs tracking-widest">Riesgos Específicos Identificados</h3>
                </div>
                <div className="grid sm:grid-cols-2 gap-4">
                  {result.riesgos.map((riesgo, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="flex items-start gap-3 p-4 rounded-2xl bg-black/20 border border-white/5 hover:border-white/10 transition-colors"
                    >
                      <div className="mt-1 w-1.5 h-1.5 rounded-full bg-red-500 shrink-0"></div>
                      <span className="text-sm text-zinc-400 font-medium">{riesgo}</span>
                    </motion.div>
                  ))}
                </div>
              </div>

              {/* Technical Disclaimer */}
              <div className="text-center pt-8 border-t border-zinc-800/50">
                <p className="text-[10px] text-zinc-600 font-mono uppercase tracking-[0.3em]">
                  Analysis powered by Gemini Sec-Protocol v2.0 • Real-time Threat Intelligence
                </p>
              </div>
            </motion.div>
          )}

          {!result && !loading && (
            <div className="mt-20 text-center space-y-6 border border-zinc-800/20 py-20 rounded-3xl">
              <div className="mx-auto w-16 h-16 bg-zinc-900 border border-zinc-800 rounded-3xl flex items-center justify-center mb-6 rotate-3">
                <ExternalLink className="w-6 h-6 text-zinc-700" />
              </div>
              <h3 className="text-zinc-400 font-medium">El sistema está listo para el escaneo.</h3>
              <p className="text-zinc-600 text-sm max-w-sm mx-auto">
                Ingrese una URL sospechosa arriba para iniciar el análisis heurístico y de comportamiento por IA.
              </p>
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
