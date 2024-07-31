class AnomalyDetector {
  constructor(config) {
    this.config = config;
    this.normalBehavior = {
      avgLength: 0,
      stdDevLength: 0,
      commonActions: new Set(),
      successRate: 0
    };
    this.samples = [];
  }

  isAnomaly(result) {
    if (this.samples.length < this.config.minSamples) {
      this.samples.push(result);
      return false;
    }

    if (this.samples.length === this.config.minSamples) {
      this.calculateNormalBehavior();
    }

    const lengthScore = this.getLengthAnomalyScore(result.payload);
    const actionScore = this.getActionAnomalyScore(result.actions);
    const successScore = this.getSuccessAnomalyScore(result);

    const anomalyScore = (lengthScore + actionScore + successScore) / 3;

    if (anomalyScore > this.config.threshold) {
      return true;
    }

    this.updateNormalBehavior(result);
    return false;
  }

  calculateNormalBehavior() {
    const lengths = this.samples.map(s => s.payload.length);
    this.normalBehavior.avgLength = lengths.reduce((a, b) => a + b) / lengths.length;
    this.normalBehavior.stdDevLength = Math.sqrt(lengths.map(x => Math.pow(x - this.normalBehavior.avgLength, 2)).reduce((a, b) => a + b) / lengths.length);

    const actionCounts = {};
    for (const sample of this.samples) {
      for (const action of sample.actions) {
        actionCounts[action] = (actionCounts[action] || 0) + 1;
      }
    }
    this.normalBehavior.commonActions = new Set(
      Object.entries(actionCounts)
        .filter(([, count]) => count > this.samples.length * 0.1)
        .map(([action]) => action)
    );

    this.normalBehavior.successRate = this.samples.filter(s => s.success).length / this.samples.length;
  }

  getLengthAnomalyScore(payload) {
    const zScore = Math.abs(payload.length - this.normalBehavior.avgLength) / this.normalBehavior.stdDevLength;
    return 1 - 1 / (1 + zScore);
  }

  getActionAnomalyScore(actions) {
    const uncommonActions = actions.filter(action => !this.normalBehavior.commonActions.has(action));
    return uncommonActions.length / actions.length;
  }

  getSuccessAnomalyScore(result) {
    return Math.abs(result.success ? 1 : 0 - this.normalBehavior.successRate);
  }

  updateNormalBehavior(result) {
    this.samples.push(result);
    if (this.samples.length > this.config.maxSamples) {
      this.samples.shift();
    }
    this.calculateNormalBehavior();
  }
}

module.exports = { AnomalyDetector };