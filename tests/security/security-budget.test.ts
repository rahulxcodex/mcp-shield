import { BudgetTracker, SecurityBudgetExceededError } from '../../src/security/budget/security-budget';

describe('Roadmap Step 2 — Security Resource Budgets', () => {
  it('enforces maximum payload byte consumption', () => {
    const tracker = new BudgetTracker({ maxBytes: 1000 });
    tracker.consumeBytes(500);
    expect(tracker.getStats().bytesConsumed).toBe(500);

    expect(() => {
      tracker.consumeBytes(600); // 1100 > 1000
    }).toThrow(SecurityBudgetExceededError);
  });

  it('enforces maximum AST recursion depth', () => {
    const tracker = new BudgetTracker({ maxDepth: 10 });
    tracker.recordDepth(5);

    expect(() => {
      tracker.recordDepth(12);
    }).toThrow(SecurityBudgetExceededError);
  });

  it('enforces graph traversal node limits', () => {
    const tracker = new BudgetTracker({ maxGraphNodes: 50 });
    tracker.incrementNodes(25);

    expect(() => {
      tracker.incrementNodes(30);
    }).toThrow(SecurityBudgetExceededError);
  });

  it('enforces analysis deadline timeout', async () => {
    const tracker = new BudgetTracker({ maxAnalysisMs: 10 });
    await new Promise(resolve => setTimeout(resolve, 25));

    expect(() => {
      tracker.checkDeadline();
    }).toThrow(SecurityBudgetExceededError);
  });
});
