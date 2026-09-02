export interface NodeStatus {
  nodeId: string;
  version: string;
  lastHeartbeat: Date;
  activePolicies: string[];
}

export class FleetManager {
  private nodes: Map<string, NodeStatus> = new Map();
  private globalPolicies: string[] = [];

  /**
   * Distribute OPA/Rego policies to all connected nodes via GitOps
   */
  public distributePolicies(policies: string[]): void {
    this.globalPolicies = policies;
    this.nodes.forEach((status, nodeId) => {
      // Simulate pushing policies to node
      status.activePolicies = [...this.globalPolicies];
      console.log(`Pushed ${policies.length} policies to node ${nodeId}`);
    });
  }

  /**
   * Register a new MCP Shield proxy node
   */
  public registerNode(nodeId: string, version: string): void {
    this.nodes.set(nodeId, {
      nodeId,
      version,
      lastHeartbeat: new Date(),
      activePolicies: [...this.globalPolicies],
    });
  }

  /**
   * Check fleet health
   */
  public checkFleetHealth(): { total: number; healthy: number } {
    const now = new Date();
    let healthy = 0;
    this.nodes.forEach((node) => {
      const diffMs = now.getTime() - node.lastHeartbeat.getTime();
      if (diffMs < 60000) { // 1 minute
        healthy++;
      }
    });
    return { total: this.nodes.size, healthy };
  }
}
