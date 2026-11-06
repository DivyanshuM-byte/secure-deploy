import type { Metadata } from "next";
import { Navbar } from "@/components/Navbar";
import "./globals.css";

export const metadata: Metadata = {
  title: "secure-deploy — DevSecOps Pre-Deployment Security Gate",
  description: "Automated pre-deployment scanning for hardcoded secrets, PII, and infrastructure keys.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col font-sans antialiased selection:bg-emerald-500/30 selection:text-emerald-200">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-slate-800/80 bg-[#080C14] py-6 text-xs text-slate-500">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
            <span>secure-deploy · DevSecOps Pre-Deployment Gate</span>
            <span className="font-mono">
              Secrets · PII · Infrastructure Files · 0-100 Risk Engine
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
