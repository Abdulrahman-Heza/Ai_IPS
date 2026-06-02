import { networkNodeRepository } from '../database/repositories/NetworkNodeRepository';
import { NetworkNode, NodeType, NodeStatus, AppError } from '../types';
import { logger } from '../utils/logger';

export class NetworkNodeService {
  /**
   * Register a new network node
   */
  async registerNode(org_id: number, node: Omit<NetworkNode, 'id' | 'created_at' | 'updated_at'>): Promise<NetworkNode> {
    logger.info(`Registering network node: ${node.ip_address} in org ${org_id}`);

    // Check if already exists
    const existing = await networkNodeRepository.findByIP(node.ip_address, org_id);
    if (existing) {
      throw new AppError(
        'NODE_EXISTS',
        409,
        `Node with IP ${node.ip_address} already registered`
      );
    }

    return await networkNodeRepository.create(org_id, node);
  }

  /**
   * Get node details
   */
  async getNode(org_id: number, node_id: number): Promise<NetworkNode | null> {
    const node = await networkNodeRepository.findById(node_id);

    if (!node || node.organization_id !== org_id) {
      throw new AppError(
        'NODE_NOT_FOUND',
        404,
        'Network node not found'
      );
    }

    return node;
  }

  /**
   * List all nodes
   */
  async listNodes(org_id: number, limit = 100, offset = 0): Promise<{
    total: number;
    data: NetworkNode[];
  }> {
    const data = await networkNodeRepository.findAll(org_id, limit, offset);
    const total = await networkNodeRepository.count(org_id);

    return { total, data };
  }

  /**
   * Get nodes by type
   */
  async getNodesByType(org_id: number, node_type: NodeType): Promise<NetworkNode[]> {
    return await networkNodeRepository.findByType(org_id, node_type);
  }

  /**
   * Get online nodes only
   */
  async getOnlineNodes(org_id: number): Promise<NetworkNode[]> {
    return await networkNodeRepository.findOnline(org_id);
  }

  /**
   * Update node
   */
  async updateNode(org_id: number, node_id: number, updates: Partial<NetworkNode>): Promise<NetworkNode | null> {
    const node = await this.getNode(org_id, node_id);

    if (!node) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Network node not found');
    }

    return await networkNodeRepository.update(node_id, updates);
  }

  /**
   * Update node status
   */
  async updateNodeStatus(org_id: number, node_id: number, status: NodeStatus): Promise<void> {
    const node = await this.getNode(org_id, node_id);

    if (!node) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Network node not found');
    }

    await networkNodeRepository.updateStatus(node_id, status);
    logger.info(`Node ${node_id} status updated to ${status}`);
  }

  /**
   * Record heartbeat from node
   */
  async recordHeartbeat(org_id: number, node_id: number): Promise<void> {
    const node = await this.getNode(org_id, node_id);

    if (!node) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Network node not found');
    }

    await networkNodeRepository.updateHeartbeat(node_id);

    // Auto-update status to online if was offline
    if (node.status !== 'online') {
      await networkNodeRepository.updateStatus(node_id, 'online');
    }
  }

  /**
   * Mark node as suspicious
   */
  async markSuspicious(org_id: number, node_id: number, reason: string): Promise<void> {
    const node = await this.getNode(org_id, node_id);

    if (!node) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Network node not found');
    }

    await networkNodeRepository.updateStatus(node_id, 'suspicious');
    logger.warn(`Node ${node_id} marked suspicious: ${reason}`);
  }

  /**
   * Delete node
   */
  async deleteNode(org_id: number, node_id: number): Promise<boolean> {
    const node = await this.getNode(org_id, node_id);

    if (!node) {
      throw new AppError('NODE_NOT_FOUND', 404, 'Network node not found');
    }

    return await networkNodeRepository.delete(node_id);
  }

  /**
   * Get network health summary
   */
  async getHealthSummary(org_id: number): Promise<{
    total: number;
    online: number;
    offline: number;
    suspicious: number;
    health_percentage: number;
  }> {
    const stats = await networkNodeRepository.getHealthStats(org_id);

    const health_percentage = stats.total > 0 ? Math.round((stats.online / stats.total) * 100) : 0;

    return {
      ...stats,
      health_percentage,
    };
  }
}

export const networkNodeService = new NetworkNodeService();
