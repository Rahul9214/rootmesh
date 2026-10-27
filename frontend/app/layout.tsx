import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { ClerkProvider } from "@clerk/nextjs";
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
  const clerkPublishableKey =
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ||
    process.env.CLERK_PUBLISHABLE_KEY;

  const content = (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-[#FAF7F2] text-[#302B30] antialiased min-h-screen font-sans selection:bg-[#D26A50]/20 selection:text-[#302B30]">
        {children}
      </body>
    </html>
  );

  if (!clerkPublishableKey) {
    return content;
  }

  return (
    <ClerkProvider
      publishableKey={clerkPublishableKey}
      appearance={{
        variables: {
          colorPrimary: "#D26A50",
          colorForeground: "#302B30",
          colorBackground: "#FAF7F2",
          colorInput: "#FAF7F2",
          colorInputForeground: "#302B30",
          fontFamily: "var(--font-inter), sans-serif",
          borderRadius: "0.5rem",
        },
        elements: {
          card: "border border-[#DFD6C9] shadow-subtle bg-[#FAF7F2]",
          formButtonPrimary:
            "bg-[#D26A50] hover:bg-[#BE5B42] text-white shadow-terracotta-xs transition-colors font-medium",
          organizationSwitcherTrigger:
            "border border-[#DFD6C9] bg-[#FAF7F2] text-[#302B30] hover:bg-[#F5EFE6] px-2.5 py-1 text-xs font-mono rounded-md",
          userButtonAvatarBox: "w-7 h-7 border border-[#DFD6C9]",
        },
      }}
    >
      {content}
    </ClerkProvider>
  );
}
