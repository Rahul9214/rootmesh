# RootMesh — Next.js Operations Frontend

Modern, high-performance cybersecurity operations console for **RootMesh**, built with Next.js 15.5, React 19, Tailwind CSS v4, and Framer Motion.

## Key Component Architecture

- **`app/page.tsx`**: Main operations console integrating authentication, public landing, and operational workspaces.
- **`components/PublicLandingExperience.tsx`**: Pre-rendered public landing page and interactive product walkthrough.
- **`components/HeroSection.tsx`**: Operations command center, Patient Zero selection, and telemetry strip.
- **`components/IncidentJourneyTimeline.tsx`**: 8-stage Human-in-the-Loop lifecycle visualizer.
- **`components/GraphCanvas.tsx`**: Interactive FalkorDB topology explorer canvas.
- **`components/SwipeableCardStack.tsx`**: Incident triage deck with gesture, keyboard, and click controls.
- **`components/FallingBlockGrid.tsx`**: Live threat propagation matrix and containment trigger.
- **`components/RiskPrioritiesDeck.tsx`**: PageRank-ordered structural choke point evaluation.
- **`components/CompanyBrainDossier.tsx`**: Organizational ownership, on-call responders, runbook links, and audit receipts.
- **`components/NetworkGridBackground.tsx`**: SVG connected network architectural background.

## Available Scripts

```bash
# Start development server with Turbopack
npm run dev

# Run unit and truthfulness test suite
npm test

# Run ESLint validation
npm run lint

# Run strict TypeScript type checking
npx tsc --noEmit

# Build optimized production bundle & standalone assets
npm run build

# Start production standalone server
node .next/standalone/server.js
```

## Environment Configuration

Copy `.env.example` to `.env.local` to configure local variables:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
```
