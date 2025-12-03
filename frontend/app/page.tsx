"use client";

import Image from "next/image";
import Link from "next/link";
import { motion, useScroll, useTransform } from "framer-motion";
import { Terminal } from "@/components/Terminal";
import { TiltCard } from "@/components/TiltCard";
import { Search, FileText, Shield, ArrowRight, Terminal as TerminalIcon, Database, Copy, Check, Github, Key } from "lucide-react";
import { useState, useRef } from "react";

export default function Home() {
  const [activeTab, setActiveTab] = useState<'ip' | 'file' | 'search'>('ip');
  const [copied, setCopied] = useState(false);
  const targetRef = useRef(null);
  const { scrollYProgress } = useScroll({
    target: targetRef,
    offset: ["start start", "end start"]
  });

  const opacity = useTransform(scrollYProgress, [0, 0.5], [1, 0]);
  const scale = useTransform(scrollYProgress, [0, 0.5], [1, 0.8]);
  const y = useTransform(scrollYProgress, [0, 0.5], [0, -50]);

  const copyToClipboard = () => {
    navigator.clipboard.writeText("go install github.com/crowdsecurity/ipdex/cmd/ipdex@latest");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 }
  };

  return (
    <main className="min-h-screen bg-white selection:bg-purple-100 selection:text-purple-900 overflow-hidden perspective-1000" ref={targetRef}>
      {/* Background Gradients & Floating Elements */}
      <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
        <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-purple-200/30 rounded-full blur-[120px] animate-pulse" />
        <div className="absolute top-[20%] right-[-5%] w-[30%] h-[30%] bg-blue-200/30 rounded-full blur-[100px] animate-pulse delay-700" />
        <div className="absolute bottom-[-10%] left-[20%] w-[35%] h-[35%] bg-teal-100/30 rounded-full blur-[120px] animate-pulse delay-1000" />

        {/* Floating 3D Shapes */}
        <motion.div
          animate={{ rotate: 360, y: [0, -20, 0] }}
          transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
          className="absolute top-20 right-20 w-20 h-20 border-4 border-purple-200/20 rounded-xl rotate-12 backdrop-blur-sm"
        />
        <motion.div
          animate={{ rotate: -360, y: [0, 30, 0] }}
          transition={{ duration: 25, repeat: Infinity, ease: "linear" }}
          className="absolute bottom-40 left-10 w-32 h-32 border-4 border-blue-200/20 rounded-full backdrop-blur-sm"
        />
      </div>

      {/* Navigation */}
      <nav className="fixed w-full z-50 bg-white/70 backdrop-blur-xl border-b border-white/20 supports-[backdrop-filter]:bg-white/60">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative w-8 h-8">
              <Image src="/logo.svg" alt="ipdex logo" fill className="object-contain" />
            </div>
            <span className="font-bold text-xl tracking-tight text-slate-900">ipdex</span>
          </div>
          <div className="flex items-center gap-6">
            <Link
              href="https://github.com/crowdsecurity/ipdex"
              className="group flex items-center gap-2 text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors hidden sm:flex"
            >
              <Github className="w-5 h-5 group-hover:scale-110 transition-transform" />
              <span>GitHub</span>
            </Link>
            <Link
              href="https://app.crowdsec.net/"
              className="flex items-center gap-2 text-sm font-medium text-white bg-slate-900 px-5 py-2.5 rounded-full hover:bg-slate-800 transition-all hover:shadow-lg hover:shadow-slate-200 active:scale-95 group"
            >
              <Key className="w-4 h-4 group-hover:rotate-45 transition-transform" />
              <span>Get API Key</span>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative z-10 pt-32 pb-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <motion.div
          className="text-center max-w-4xl mx-auto"
          initial="hidden"
          animate="visible"
          variants={containerVariants}
          style={{ opacity, scale, y }}
        >
          <motion.div variants={itemVariants} className="flex justify-center mb-10 perspective-500">
            <motion.div
              className="relative w-32 h-32 sm:w-40 sm:h-40 group cursor-pointer"
              whileHover={{ rotateY: 180 }}
              transition={{ duration: 0.8 }}
              style={{ transformStyle: "preserve-3d" }}
            >
              <div className="absolute inset-0 bg-purple-500/20 rounded-full blur-2xl group-hover:blur-3xl transition-all duration-500" />
              <Image
                src="/logo.svg"
                alt="ipdex logo"
                fill
                className="object-contain drop-shadow-2xl relative z-10"
                priority
              />
            </motion.div>
          </motion.div>

          <motion.h1
            variants={itemVariants}
            className="text-5xl sm:text-7xl font-bold tracking-tight text-slate-900 mb-8"
          >
            Your Ultimate <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-600 via-blue-600 to-teal-500 animate-gradient-x bg-300% animate-shine">IP Dex</span>
          </motion.h1>

          <motion.p
            variants={itemVariants}
            className="text-xl text-slate-600 mb-12 max-w-2xl mx-auto leading-relaxed"
          >
            The CLI tool that puts CrowdSec's Cyber Threat Intelligence at your fingertips.
            Scan IPs, analyze logs, and hunt threats with ease.
          </motion.p>

          <motion.div
            variants={itemVariants}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link
              href="#install"
              className="w-full sm:w-auto px-8 py-4 bg-purple-600 text-white rounded-full font-medium hover:bg-purple-700 transition-all flex items-center justify-center gap-2 shadow-xl shadow-purple-200 hover:shadow-purple-300 hover:-translate-y-1 hover:scale-105"
            >
              Download ipdex <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="https://app.crowdsec.net/"
              className="w-full sm:w-auto px-8 py-4 bg-white text-slate-900 border border-slate-200 rounded-full font-medium hover:bg-slate-50 transition-all flex items-center justify-center gap-2 hover:border-slate-300 hover:shadow-md hover:-translate-y-1 hover:scale-105 group"
            >
              <Key className="w-4 h-4 group-hover:text-purple-600 transition-colors" />
              Get API Key
            </Link>
          </motion.div>
        </motion.div>
      </section>

      {/* Demo Section */}
      <section className="relative z-10 py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-6 text-slate-900">See it in Action</h2>
            <div className="inline-flex p-1 bg-slate-100 rounded-full">
              {(['ip', 'file', 'search'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-6 py-2 rounded-full text-sm font-medium transition-all duration-300 ${activeTab === tab
                    ? 'bg-white text-slate-900 shadow-sm scale-105'
                    : 'text-slate-500 hover:text-slate-700'
                    }`}
                >
                  {tab === 'ip' ? 'Scan IP' : tab === 'file' ? 'Scan File' : 'Search CTI'}
                </button>
              ))}
            </div>
          </div>

          <div className="max-w-4xl mx-auto perspective-1000">
            <motion.div
              className="relative group"
              initial={{ rotateX: 10, opacity: 0 }}
              whileInView={{ rotateX: 0, opacity: 1 }}
              transition={{ duration: 0.8, type: "spring" }}
              viewport={{ once: true }}
            >
              <div className="absolute -inset-1 bg-gradient-to-r from-purple-600 to-blue-600 rounded-xl blur opacity-20 group-hover:opacity-40 transition duration-1000 group-hover:duration-200" />
              {activeTab === 'ip' ? (
                <motion.div
                  className="relative rounded-lg overflow-hidden shadow-2xl"
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5 }}
                >
                  <Image
                    src="/screenshots/scan-ip.png"
                    alt="ipdex scan ip output"
                    width={800}
                    height={600}
                    className="w-full h-auto"
                  />
                </motion.div>
              ) : (
                <Terminal
                  title={`ipdex ${activeTab === 'file' ? 'file nginx.log' : 'search "cves:CVE-2025-2748"'}`}
                  className="relative bg-[#1e1e1e]/95 backdrop-blur-xl shadow-2xl"
                >
                  {activeTab === 'file' && (
                    <div className="space-y-2 font-mono">
                      <div className="flex gap-2">
                        <span className="text-green-400">➜</span>
                        <span className="text-blue-400">~</span>
                        <span className="text-gray-300">ipdex file /var/log/nginx/access.log</span>
                      </div>
                      <div className="text-gray-300 space-y-1">
                        <p>Scanning <span className="text-yellow-300">/var/log/nginx/access.log</span>...</p>
                        <p>Found <span className="text-white font-bold">154</span> unique IPs.</p>
                        <div className="flex items-center gap-2 py-2">
                          <span>Enriching</span>
                          <div className="w-32 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: "100%" }}
                              transition={{ duration: 1.5, ease: "easeInOut" }}
                              className="h-full bg-green-400"
                            />
                          </div>
                        </div>
                        <div className="bg-gray-800/50 p-4 rounded-lg border border-gray-700 mt-2">
                          <p className="text-gray-400 text-xs uppercase tracking-wider mb-2">Report Summary #42</p>
                          <div className="grid grid-cols-3 gap-4 text-center">
                            <div>
                              <div className="text-2xl font-bold text-white">154</div>
                              <div className="text-xs text-gray-500">Total IPs</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-red-400">12</div>
                              <div className="text-xs text-gray-500">Malicious</div>
                            </div>
                            <div>
                              <div className="text-2xl font-bold text-green-400">142</div>
                              <div className="text-xs text-gray-500">Safe</div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                  {activeTab === 'search' && (
                    <div className="space-y-2 font-mono">
                      <div className="flex gap-2">
                        <span className="text-green-400">➜</span>
                        <span className="text-blue-400">~</span>
                        <span className="text-gray-300">ipdex search "cves:CVE-2025-2748"</span>
                      </div>
                      <div className="text-gray-300">
                        <p>Searching CrowdSec CTI for <span className="text-cyan-300">"cves:CVE-2025-2748"</span>...</p>
                        <p className="py-2">Found <span className="text-white font-bold">2,450</span> IPs associated with this CVE.</p>

                        <div className="grid grid-cols-2 gap-4 mt-2">
                          <div className="bg-gray-800/30 p-3 rounded border border-gray-700">
                            <p className="text-xs text-gray-500 mb-2 uppercase">Top ASNs</p>
                            <div className="space-y-1 text-sm">
                              <div className="flex justify-between">
                                <span>AS12345</span>
                                <span className="text-gray-400">450</span>
                              </div>
                              <div className="flex justify-between">
                                <span>AS67890</span>
                                <span className="text-gray-400">320</span>
                              </div>
                            </div>
                          </div>
                          <div className="bg-gray-800/30 p-3 rounded border border-gray-700">
                            <p className="text-xs text-gray-500 mb-2 uppercase">Top Countries</p>
                            <div className="space-y-1 text-sm">
                              <div className="flex justify-between">
                                <span>🇺🇸 US</span>
                                <span className="text-gray-400">800</span>
                              </div>
                              <div className="flex justify-between">
                                <span>🇨🇳 CN</span>
                                <span className="text-gray-400">600</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </Terminal>
              )}
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="relative z-10 py-24 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <div className="grid md:grid-cols-3 gap-8">
          <TiltCard className="h-full">
            <div className="p-8 rounded-3xl bg-white border border-slate-100 shadow-xl shadow-slate-200/50 h-full">
              <div className="w-14 h-14 bg-purple-50 rounded-2xl flex items-center justify-center mb-6">
                <Shield className="w-7 h-7 text-purple-600" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-slate-900">IP Reputation</h3>
              <p className="text-slate-600 leading-relaxed">
                Instantly check if an IP is malicious, what attacks it's performed, and its background information.
              </p>
            </div>
          </TiltCard>

          <TiltCard className="h-full">
            <div className="p-8 rounded-3xl bg-white border border-slate-100 shadow-xl shadow-slate-200/50 h-full">
              <div className="w-14 h-14 bg-blue-50 rounded-2xl flex items-center justify-center mb-6">
                <FileText className="w-7 h-7 text-blue-600" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-slate-900">Log Analysis</h3>
              <p className="text-slate-600 leading-relaxed">
                Feed log files to ipdex and get a comprehensive report on all IPs found within them.
              </p>
            </div>
          </TiltCard>

          <TiltCard className="h-full">
            <div className="p-8 rounded-3xl bg-white border border-slate-100 shadow-xl shadow-slate-200/50 h-full">
              <div className="w-14 h-14 bg-teal-50 rounded-2xl flex items-center justify-center mb-6">
                <Search className="w-7 h-7 text-teal-600" />
              </div>
              <h3 className="text-xl font-bold mb-3 text-slate-900">Advanced Search</h3>
              <p className="text-slate-600 leading-relaxed">
                Leverage the full power of CrowdSec's CTI database with complex search queries.
              </p>
            </div>
          </TiltCard>
        </div>
      </section>

      {/* Installation Section */}
      <section id="install" className="relative z-10 py-24 bg-slate-900 text-white overflow-hidden">
        <div className="absolute inset-0 bg-[url('/grid.svg')] opacity-10" />
        <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-b from-slate-900 via-transparent to-slate-900" />

        <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl sm:text-4xl font-bold mb-8">Get Started in Seconds</h2>
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-8 text-left font-mono text-sm sm:text-base border border-slate-700 shadow-2xl relative group hover:border-purple-500/50 transition-colors">
            <div className="flex justify-between items-center mb-4 text-slate-400">
              <span className="flex items-center gap-2">
                <TerminalIcon className="w-4 h-4" />
                Install with Go
              </span>
              <button
                onClick={copyToClipboard}
                className="flex items-center gap-2 hover:text-white transition-colors bg-slate-700/50 px-3 py-1 rounded-full text-xs"
              >
                {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <code className="text-purple-400 block break-all">
              go install github.com/crowdsecurity/ipdex/cmd/ipdex@latest
            </code>
          </div>
          <div className="mt-12 flex flex-wrap justify-center gap-8 text-slate-400">
            <div className="flex items-center gap-3 bg-slate-800/30 px-4 py-2 rounded-full border border-slate-800">
              <TerminalIcon className="w-5 h-5 text-slate-300" />
              <span>macOS</span>
            </div>
            <div className="flex items-center gap-3 bg-slate-800/30 px-4 py-2 rounded-full border border-slate-800">
              <Database className="w-5 h-5 text-slate-300" />
              <span>Linux</span>
            </div>
            <div className="flex items-center gap-3 bg-slate-800/30 px-4 py-2 rounded-full border border-slate-800">
              <Shield className="w-5 h-5 text-slate-300" />
              <span>Windows</span>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 py-12 border-t border-slate-100 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2">
            <Image src="/logo.svg" alt="ipdex logo" width={24} height={24} className="opacity-50 grayscale hover:grayscale-0 transition-all" />
            <span className="font-semibold text-slate-400">ipdex</span>
          </div>
          <div className="flex gap-8 text-sm text-slate-500">
            <Link href="https://github.com/crowdsecurity/ipdex" className="hover:text-purple-600 transition-colors flex items-center gap-2">
              <Github className="w-4 h-4" />
              GitHub
            </Link>
            <Link href="https://www.crowdsec.net/" className="hover:text-purple-600 transition-colors">CrowdSec</Link>
            <Link href="https://docs.crowdsec.net/" className="hover:text-purple-600 transition-colors">Documentation</Link>
          </div>
          <div className="text-sm text-slate-400">
            © {new Date().getFullYear()} CrowdSec. MIT License.
          </div>
        </div>
      </footer>
    </main>
  );
}
