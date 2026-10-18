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
    "FalkorDB GraphBLAS-powered cybersecurity incident investigation, attack-path traversal, and persistent memory platform.",
  icons: {
    icon: "/brand/rootmesh-icon.png",
    shortcut: "/brand/rootmesh-icon.png",
    apple: "/brand/rootmesh-icon.png",
  },
  openGraph: {
    title: "RootMesh — Threat Intelligence & Incident Response",
    description: "Graph-native cybersecurity incident investigation and response engine powered by FalkorDB.",
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
      <body className="bg-[#FAF7F2] text-[#302B30] antialiased min-h-screen font-sans selection:bg-[#D26A50]/20 selection:text-[#302B30]">
        {children}
      </body>
    </html>
  );
}
