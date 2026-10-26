"use client";

import React, { useEffect, useState, useRef } from "react";

/**
 * RootMesh Signature Connected Network-Grid Background
 *
 * Visual Concept:
 * - Architectural infrastructure network canvas on warm ivory (#FAF7F2).
 * - Faint warm-gray grid lines (#E8E0D5) forming the structural mesh.
 * - Distinctive terracotta (#D26A50) and plum (#82465D) junction nodes at selective grid intersections.
 * - Architectural routing segments representing lateral network traces.
 * - Smooth vertical gradient mask fading gracefully behind information-dense operational sections.
 * - Desktop pointer-responsive ambient spotlight (GPU/CPU-restrained, 60fps RAF throttled).
 * - Inert on touch/mobile devices and disables when prefers-reduced-motion is active.
 * - Purely decorative (aria-hidden="true", pointer-events-none).
 */
export const NetworkGridBackground: React.FC = () => {
  const [mousePos, setMousePos] = useState<{ x: number; y: number } | null>(null);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    // Only enable pointer-responsive spotlight on desktop devices with fine pointer
    if (typeof window === "undefined") return;

    const hasFinePointer = window.matchMedia("(pointer: fine)").matches;
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (!hasFinePointer || prefersReducedMotion) {
      return;
    }

    const handleMouseMove = (e: MouseEvent) => {
      if (rafRef.current !== null) return;
      rafRef.current = requestAnimationFrame(() => {
        setMousePos({ x: e.clientX, y: e.clientY });
        rafRef.current = null;
      });
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
      }
    };
  }, []);

  return (
    <div
      aria-hidden="true"
      className="fixed inset-0 pointer-events-none z-0 overflow-hidden"
      style={{
        backgroundColor: "#FAF7F2",
      }}
    >
      {/* ── Signature Architectural Connected SVG Network Mesh ── */}
      <svg
        className="absolute inset-0 w-full h-full opacity-85"
        xmlns="http://www.w3.org/2000/svg"
        style={{
          maskImage: "linear-gradient(to bottom, rgba(0,0,0,0.95) 0%, rgba(0,0,0,0.75) 500px, rgba(0,0,0,0.55) 1200px, rgba(0,0,0,0.45) 2200px, rgba(0,0,0,0.50) 100%)",
          WebkitMaskImage: "linear-gradient(to bottom, rgba(0,0,0,0.95) 0%, rgba(0,0,0,0.75) 500px, rgba(0,0,0,0.55) 1200px, rgba(0,0,0,0.45) 2200px, rgba(0,0,0,0.50) 100%)",
        }}
      >
        <defs>
          {/* Base Grid Pattern: 48px square architectural mesh */}
          <pattern id="rootmesh-grid" width="48" height="48" patternUnits="userSpaceOnUse">
            <path
              d="M 48 0 L 0 0 0 48"
              fill="none"
              stroke="#DFD6C9"
              strokeWidth="0.85"
              strokeOpacity="0.85"
            />
            {/* Subtle sub-grid intersection tick */}
            <circle cx="0" cy="0" r="1.25" fill="#CDBFB0" fillOpacity="0.75" />
          </pattern>

          {/* Large Architectural Block Pattern: 192px super-grid with accent nodes */}
          <pattern id="rootmesh-macro-grid" width="192" height="192" patternUnits="userSpaceOnUse">
            {/* Macro boundary line */}
            <path
              d="M 192 0 L 0 0 0 192"
              fill="none"
              stroke="#D4C9BA"
              strokeWidth="1"
              strokeOpacity="0.6"
            />

            {/* Junction Node: Terracotta Vertex */}
            <circle cx="0" cy="0" r="3" fill="#D26A50" fillOpacity="0.75" />
            <circle cx="0" cy="0" r="6" fill="none" stroke="#D26A50" strokeWidth="0.75" strokeOpacity="0.3" />

            {/* Junction Node: Plum Vertex */}
            <circle cx="96" cy="96" r="2.5" fill="#82465D" fillOpacity="0.65" />
            <circle cx="96" cy="96" r="5" fill="none" stroke="#82465D" strokeWidth="0.5" strokeOpacity="0.25" />

            {/* Architectural Network Traces (connecting segments) */}
            <path
              d="M 0 0 L 48 0 L 48 48 M 96 96 L 144 96 L 144 144"
              fill="none"
              stroke="#D26A50"
              strokeWidth="0.85"
              strokeOpacity="0.3"
              strokeDasharray="2 4"
            />
            <path
              d="M 96 96 L 96 48 L 144 48"
              fill="none"
              stroke="#82465D"
              strokeWidth="0.85"
              strokeOpacity="0.28"
              strokeDasharray="3 3"
            />

            {/* Micro Junction Accent Block */}
            <rect
              x="46"
              y="46"
              width="4"
              height="4"
              fill="#E0D6C8"
              stroke="#C4B6A4"
              strokeWidth="0.75"
            />
          </pattern>
        </defs>

        {/* Fill viewport with Base Mesh */}
        <rect width="100%" height="100%" fill="url(#rootmesh-grid)" />

        {/* Fill viewport with Macro Accent Network */}
        <rect width="100%" height="100%" fill="url(#rootmesh-macro-grid)" />
      </svg>

      {/* ── Desktop Pointer Ambient Spotlight (Subtle warm highlight) ── */}
      {mousePos && (
        <div
          className="absolute inset-0 pointer-events-none transition-opacity duration-300 hidden md:block"
          style={{
            background: `radial-gradient(circle 380px at ${mousePos.x}px ${mousePos.y}px, rgba(210, 106, 80, 0.05) 0%, rgba(130, 70, 93, 0.025) 50%, transparent 100%)`,
          }}
        />
      )}

      {/* ── Top Atmospheric Ambient Glow (Warm Ivory to Terracotta/Plum tint) ── */}
      <div
        className="absolute top-0 left-0 right-0 h-96 pointer-events-none"
        style={{
          background: "radial-gradient(ellipse 65% 50% at 50% -10%, rgba(210, 106, 80, 0.06) 0%, rgba(130, 70, 93, 0.035) 45%, transparent 100%)",
        }}
      />
    </div>
  );
};
