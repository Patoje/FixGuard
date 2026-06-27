import type { AttackRecommendation } from '../intelligence/AttackRecommendation';

export interface RecommendationInbox {
  add(recommendation: AttackRecommendation): void;
  listPending(): AttackRecommendation[];
  get(id: string): AttackRecommendation | undefined;
  remove(id: string): void;
}

export class LocalRecommendationInbox implements RecommendationInbox {
  private pending = new Map<string, AttackRecommendation>();

  add(recommendation: AttackRecommendation): void {
    this.pending.set(recommendation.id, recommendation);
  }

  listPending(): AttackRecommendation[] {
    return Array.from(this.pending.values());
  }

  get(id: string): AttackRecommendation | undefined {
    return this.pending.get(id);
  }

  remove(id: string): void {
    this.pending.delete(id);
  }
}
