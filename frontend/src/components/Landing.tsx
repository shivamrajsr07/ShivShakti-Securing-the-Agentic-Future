import { ArrowRight, BrainCircuit, Fingerprint, Globe, LockKeyhole, Radio, ShieldCheck, Sparkles, Terminal, Zap } from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "./ui/Button";

const securityLayers = [
  ["Prompt Injection", "Live jailbreak blocking", "critical"],
  ["Identity Trust", "Signed agent sessions", "verified"],
  ["Tool Control", "Least-privilege execution", "guarded"],
  ["Browser Safety", "Phishing and download defense", "active"]
] as const;

export function Landing({ onEnter }: { onEnter: () => void }) {
  return (
    <section className="cyber-shell relative min-h-screen overflow-hidden text-white">
      <img
        src="/assets/cyber-command-hero.png"
        alt=""
        className="absolute inset-0 h-full w-full object-cover object-center opacity-70"
      />
      <div className="cyber-grid" />
      <div className="scanline" />
      <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(5,11,18,0.98)_0%,rgba(5,11,18,0.9)_36%,rgba(5,11,18,0.45)_68%,rgba(5,11,18,0.18)_100%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(5,11,18,0.18)_0%,rgba(5,11,18,0.08)_46%,rgba(5,11,18,0.96)_100%)]" />
      <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-signal/80 to-transparent" />

      <div className="relative mx-auto flex min-h-screen max-w-7xl flex-col px-5 py-5 sm:px-6">
        <nav className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-md bg-signal text-ink shadow-[0_0_34px_rgba(37,208,162,0.35)]">
              <ShieldCheck size={22} />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-100">ShivShakti</p>
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Cyber Crime Defense OS</p>
            </div>
          </div>
          <Button onClick={onEnter} icon={<ArrowRight size={17} />} className="hidden sm:inline-flex">
            Open Command Center
          </Button>
        </nav>

        <div className="grid flex-1 items-center gap-8 py-10 lg:grid-cols-[0.94fr_1.06fr]">
          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55 }}
            className="max-w-2xl"
          >
            <div className="mb-5 inline-flex items-center gap-2 rounded-md border border-signal/30 bg-signal/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.16em] text-signal">
              <Sparkles size={14} />
              Cyber Crime Intelligence Platform
            </div>
            <h1 className="text-5xl font-semibold leading-tight text-white md:text-7xl">
              ShivShakti Cyber Command
            </h1>
            <p className="mt-4 text-xl font-medium text-slate-100 md:text-2xl">
              Detect. Contain. Explain. Prove.
            </p>
            <p className="mt-5 max-w-xl text-base leading-8 text-slate-300 md:text-lg">
              A live defense cockpit for cyber-crime signals and autonomous AI agents: prompt injection, credential
              leaks, unsafe tools, browser traps, IPv4/IPv6 indicators, and auditable response evidence.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button onClick={onEnter} icon={<ShieldCheck size={18} />}>Launch Live Demo</Button>
              <Button variant="secondary" onClick={onEnter} icon={<BrainCircuit size={18} />}>Threat Feed</Button>
            </div>
            <div className="mt-8 grid max-w-lg grid-cols-3 gap-3">
              {[
                ["5", "Detector lanes"],
                ["IP", "Intel scanner"],
                ["Live", "Audit stream"]
              ].map(([value, label]) => (
                <div key={label} className="border-l border-azure/40 pl-3">
                  <p className="text-2xl font-semibold text-white">{value}</p>
                  <p className="text-xs uppercase tracking-[0.12em] text-slate-400">{label}</p>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="glass-panel ml-auto w-full max-w-xl rounded-md border border-white/10 p-4 backdrop-blur-md sm:p-5"
          >
            <div className="mb-4 flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-white">Live Cyber Operations Mesh</p>
                <p className="text-xs text-slate-400">Defensive intelligence workspace</p>
              </div>
              <span className="inline-flex items-center gap-2 rounded-full border border-signal/30 bg-signal/15 px-3 py-1 text-xs text-signal">
                <Radio size={13} />
                Active
              </span>
            </div>

            <div className="mb-4 grid grid-cols-3 gap-2">
              {[
                [Zap, "Detect"],
                [LockKeyhole, "Contain"],
                [Terminal, "Investigate"]
              ].map(([Icon, label]) => (
                <div key={label as string} className="rounded-md border border-white/10 bg-white/[0.04] p-3">
                  <Icon className="mb-3 text-azure" size={18} />
                  <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-300">{label as string}</p>
                </div>
              ))}
            </div>

            <div className="grid gap-3">
              {securityLayers.map(([title, body, tag]) => (
                <div key={title} className="flex items-center justify-between gap-3 rounded-md border border-white/10 bg-ink/72 p-4">
                  <div className="flex items-center gap-3">
                    <div className="grid h-9 w-9 place-items-center rounded-md bg-azure/12 text-azure">
                      {title === "Browser Safety" ? <Globe size={18} /> : <Fingerprint size={18} />}
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-white">{title}</p>
                      <p className="text-xs text-slate-400">{body}</p>
                    </div>
                  </div>
                  <span className="shrink-0 rounded-full bg-amber/10 px-2.5 py-1 text-xs uppercase text-amber">{tag}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
