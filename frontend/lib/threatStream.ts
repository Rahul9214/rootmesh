/**
 * RootMesh Threat Stream — Authoritative Tenant-Scoped WebSocket Synchronization
 *
 * Implements hardened in-band Clerk authentication, strict tenant scoping,
 * deduplication, monotonic event ordering, and automated REST recovery upon reconnect.
 */

import {
  getAuthenticatedWebSocketUrl,
  sendWebSocketAuth,
  getCurrentPrincipal,
} from "./auth.ts";

export type ThreatStreamEventType =
  | "INCIDENT_INVESTIGATED"
  | "INCIDENT_PROPOSAL_CREATED"
  | "INCIDENT_PROPOSAL_REVIEWED"
  | "INCIDENT_CONTAINMENT_EXECUTED"
  | "ATTACK_PROPAGATION_COMPUTED";

export interface BaseThreatEvent {
  event: ThreatStreamEventType;
  tenant_id: string;
  event_id?: string;
  timestamp: number;
}

export interface IncidentInvestigatedEvent extends BaseThreatEvent {
  event: "INCIDENT_INVESTIGATED";
  incident_id: string;
  patient_zero_id?: string;
  patient_zero?: string;
  lateral_targets?: number;
  target_count?: number;
  egress_risk_mbps?: number;
  team?: string;
  responder?: string;
}

export interface ProposalCreatedEvent extends BaseThreatEvent {
  event: "INCIDENT_PROPOSAL_CREATED";
  action_id: string;
  incident_id: string;
  target_host_id: string;
  status: "PROPOSED";
  proposer: string;
}

export interface ProposalReviewedEvent extends BaseThreatEvent {
  event: "INCIDENT_PROPOSAL_REVIEWED";
  action_id: string;
  incident_id: string;
  decision: "APPROVE" | "REJECT" | "EXPIRED";
  status: "APPROVED" | "REJECTED" | "EXPIRED";
  reviewer: string;
}

export interface ContainmentExecutedEvent extends BaseThreatEvent {
  event: "INCIDENT_CONTAINMENT_EXECUTED";
  action_id: string;
  incident_id: string;
  target_host_id: string;
  status: "CONTAINED";
  paths_severed: number;
  egress_reduction_mbps: number;
  verification: string;
  executed_by: string;
}

export interface AttackPropagationEvent extends BaseThreatEvent {
  event: "ATTACK_PROPAGATION_COMPUTED";
  patient_zero: string;
  hops: number;
}

export type ThreatStreamEvent =
  | IncidentInvestigatedEvent
  | ProposalCreatedEvent
  | ProposalReviewedEvent
  | ContainmentExecutedEvent
  | AttackPropagationEvent;

export type ConnectionStatus = "connecting" | "live" | "offline";

type EventListener = (event: ThreatStreamEvent) => void;
type StatusListener = (status: ConnectionStatus) => void;
type ReconnectListener = () => void;

class ThreatStreamManager {
  private tenantId: string | null = null;
  private ws: WebSocket | null = null;
  private status: ConnectionStatus = "offline";
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryDelay = 2000;
  private isDisposed = false;
  private hasInitiallyConnected = false;

  private eventListeners = new Set<EventListener>();
  private statusListeners = new Set<StatusListener>();
  private reconnectListeners = new Set<ReconnectListener>();

  // Deduplication & monotonicity trackers
  private seenEventIds = new Set<string>();
  private latestEventTimestamps = new Map<string, number>();

  /**
   * Set active tenant and establish or switch the authoritative connection.
   */
  public setTenant(tenantId: string | null): void {
    // If a verified principal exists, strictly prioritize the Clerk-authenticated tenant identity
    const verifiedTenant = getCurrentPrincipal()?.tenant_id;
    const resolvedTenant = tenantId ? (verifiedTenant || tenantId) : null;

    if (this.tenantId === resolvedTenant) return;

    this.disconnect();
    this.tenantId = resolvedTenant;
    this.seenEventIds.clear();
    this.latestEventTimestamps.clear();
    this.hasInitiallyConnected = false;

    if (resolvedTenant) {
      this.isDisposed = false;
      this.connect();
    }
  }

  public getTenant(): string | null {
    return this.tenantId;
  }

  public getStatus(): ConnectionStatus {
    return this.status;
  }

  public subscribe(listener: EventListener): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  public onStatusChange(listener: StatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.status);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  public onReconnect(listener: ReconnectListener): () => void {
    this.reconnectListeners.add(listener);
    return () => {
      this.reconnectListeners.delete(listener);
    };
  }

  private setStatus(newStatus: ConnectionStatus): void {
    if (this.status !== newStatus) {
      this.status = newStatus;
      this.statusListeners.forEach((l) => l(newStatus));
    }
  }

  private async connect(): Promise<void> {
    if (!this.tenantId || this.isDisposed) {
      this.setStatus("offline");
      return;
    }

    if (typeof WebSocket === "undefined") {
      this.setStatus("offline");
      return;
    }

    this.setStatus("connecting");

    try {
      const url = await getAuthenticatedWebSocketUrl("/ws/threat-stream", this.tenantId);
      if (this.isDisposed) return;

      const ws = new WebSocket(url);
      this.ws = ws;

      ws.onopen = async () => {
        if (this.isDisposed || this.ws !== ws) return;
        try {
          const sent = await sendWebSocketAuth(ws, this.tenantId!);
          if (!sent && !this.isDisposed) {
            this.disconnect();
          }
        } catch {
          if (!this.isDisposed) {
            this.disconnect();
          }
        }
      };

      ws.onmessage = (event) => {
        if (this.isDisposed || this.ws !== ws) return;
        this.handleRawMessage(event.data);
      };

      ws.onclose = (event) => {
        if (this.isDisposed || this.ws !== ws) return;
        this.setStatus("offline");
        const delay = event.code === 1008 ? 8000 : this.retryDelay;
        this.retryDelay = Math.min(this.retryDelay * 1.5, 15000);
        this.retryTimer = setTimeout(() => this.connect(), delay);
      };

      ws.onerror = () => {
        if (!this.isDisposed) this.setStatus("offline");
      };
    } catch {
      if (!this.isDisposed) {
        this.setStatus("offline");
        this.retryTimer = setTimeout(() => this.connect(), 4000);
      }
    }
  }

  /**
   * Dispatches or processes raw WebSocket payload.
   * Can be invoked directly by tests to verify event filtering and state transitions.
   */
  public handleRawMessage(data: unknown): void {
    try {
      const raw = typeof data === "string" ? JSON.parse(data) : data;
      if (!raw || typeof raw !== "object") return;

      // Handle handshake auth confirmation
      if (raw.type === "auth_ok") {
        // Confirm that the backend authenticated the expected tenant
        if (this.tenantId && raw.tenant_id && raw.tenant_id !== this.tenantId) {
          console.warn(`ThreatStream: auth_ok tenant mismatch. Expected ${this.tenantId}, got ${raw.tenant_id}`);
          return;
        }
        const wasReconnect = this.hasInitiallyConnected;
        this.hasInitiallyConnected = true;
        this.setStatus("live");
        this.retryDelay = 2000;

        if (wasReconnect) {
          // Notify listeners to reconcile state via REST
          this.reconnectListeners.forEach((l) => l());
        }
        return;
      }

      // Validate event format and tenant isolation
      const evt = raw as ThreatStreamEvent;
      if (!evt.event) return;

      // Rule: Ignore cross-tenant events
      if (evt.tenant_id && this.tenantId && evt.tenant_id !== this.tenantId) {
        return;
      }

      // Deduplication: Deduplicate by event_id or composite action/event key
      const eventKey =
        evt.event_id ||
        `${evt.event}:${(evt as { incident_id?: string }).incident_id || ""}:${(evt as { action_id?: string }).action_id || ""}:${evt.timestamp || ""}`;

      if (this.seenEventIds.has(eventKey)) {
        return; // Duplicate event ignored
      }

      // Check monotonicity per incident
      const incidentId = (evt as { incident_id?: string }).incident_id;
      if (incidentId && typeof evt.timestamp === "number") {
        const lastTs = this.latestEventTimestamps.get(incidentId);
        // If an event has a timestamp strictly older by > 1.0s than the latest seen event, ignore
        if (lastTs !== undefined && evt.timestamp < lastTs - 1.0) {
          return; // Out-of-order / stale event ignored
        }
        this.latestEventTimestamps.set(incidentId, Math.max(lastTs ?? 0, evt.timestamp));
      }

      // Record in bounded deduplication set (keep max 1000 items)
      if (this.seenEventIds.size >= 1000) {
        const first = this.seenEventIds.values().next().value;
        if (first) this.seenEventIds.delete(first);
      }
      this.seenEventIds.add(eventKey);

      // Broadcast to registered listeners
      this.eventListeners.forEach((l) => l(evt));
    } catch {
      // Discard malformed JSON safely
    }
  }

  public disconnect(): void {
    this.isDisposed = true;
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.ws) {
      try {
        this.ws.close();
      } catch {}
      this.ws = null;
    }
    this.setStatus("offline");
  }
}

// Export singleton instance for authoritative, shared application subscription
export const threatStream = new ThreatStreamManager();
