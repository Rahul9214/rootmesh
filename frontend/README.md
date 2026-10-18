# RootMesh — Next.js Incident Response Frontend

Modern, high-performance cybersecurity operations interface for **RootMesh**, built with Next.js 15, React 19, and TailwindCSS.

## Architecture

- **`app/page.tsx`**: Main operations console integrating all live modules.
- **`components/HeroSection.tsx`**: Incident alert banner, trigger controls, and live agent swarm activity stream.
- **`components/FallingBlockGrid.tsx`**: Host infrastructure state cards with real-time infection status and graph-level simulated containment.
- **`components/SwipeableCardStack.tsx`**: Incident findings triage deck with real episodic memory persistence.
- **`components/GraphCanvas.tsx`**: Interactive graph visualizer link for FalkorDB topology exploration.

## Scripts

```bash
# Start development server
npm run dev

# Build optimized production bundle
npm run build

# Start production server
npm start

# Run ESLint validation
npm run lint
```

## Environment Configuration

Copy `.env.example` to `.env.local` to override defaults:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```
