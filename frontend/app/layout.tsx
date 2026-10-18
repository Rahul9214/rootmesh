import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "RootMesh — Autonomous Threat Memory & Incident Response Engine",
  description:
    "Sub-millisecond threat propagation calculation, multi-hop path reasoning, and persistent agent incident memory powered by FalkorDB GraphBLAS.",
  keywords: ["cybersecurity", "RootMesh", "FalkorDB", "GraphBLAS", "incident response", "graph AI"],
  openGraph: {
    title: "RootMesh",
    description: "FalkorDB-powered autonomous cybersecurity incident response and threat memory engine.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-[#0B0D12] text-slate-200 antialiased min-h-screen font-sans">
        {children}
      </body>
    </html>
  );
}
