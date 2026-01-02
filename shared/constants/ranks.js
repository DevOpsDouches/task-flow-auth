// constants/ranks.js
// Rank configuration and thresholds

const RANKS = {
  IRON: 'iron',
  SILVER: 'silver',
  GOLD: 'gold',
  DIAMOND: 'diamond',
  PLATINUM: 'platinum',
  TODO_MASTER: 'todo_master'
};

const RANK_THRESHOLDS = {
  iron: { min: 0, max: 9, displayName: 'Iron', color: '#9CA3AF' },
  silver: { min: 10, max: 24, displayName: 'Silver', color: '#C0C0C0' },
  gold: { min: 25, max: 49, displayName: 'Gold', color: '#FFD700' },
  diamond: { min: 50, max: 99, displayName: 'Diamond', color: '#B9F2FF' },
  platinum: { min: 100, max: 199, displayName: 'Platinum', color: '#E5E4E2' },
  todo_master: { min: 200, max: Infinity, displayName: 'Todo Master', color: '#DC2626' }
};

const RANK_ORDER = [
  RANKS.IRON,
  RANKS.SILVER,
  RANKS.GOLD,
  RANKS.DIAMOND,
  RANKS.PLATINUM,
  RANKS.TODO_MASTER
];

/**
 * Calculate rank based on completed tasks
 * @param {number} completedTasks - Total number of completed tasks
 * @returns {string} - Rank name
 */
function calculateRank(completedTasks) {
  for (const rank of RANK_ORDER) {
    const threshold = RANK_THRESHOLDS[rank];
    if (completedTasks >= threshold.min && completedTasks <= threshold.max) {
      return rank;
    }
  }
  return RANKS.IRON;
}

/**
 * Check if rank upgrade occurred
 * @param {number} oldCount - Previous completed tasks count
 * @param {number} newCount - New completed tasks count
 * @returns {Object|null} - Upgrade info or null if no upgrade
 */
function checkRankUpgrade(oldCount, newCount) {
  const oldRank = calculateRank(oldCount);
  const newRank = calculateRank(newCount);
  
  if (oldRank !== newRank) {
    return {
      fromRank: oldRank,
      toRank: newRank,
      upgraded: true
    };
  }
  
  return null;
}

/**
 * Get progress to next rank
 * @param {number} completedTasks - Total number of completed tasks
 * @returns {Object} - Progress information
 */
function getRankProgress(completedTasks) {
  const currentRank = calculateRank(completedTasks);
  const currentIndex = RANK_ORDER.indexOf(currentRank);
  
  if (currentIndex === RANK_ORDER.length - 1) {
    // Already at max rank
    return {
      currentRank,
      nextRank: null,
      progress: 100,
      tasksToNext: 0,
      isMaxRank: true
    };
  }
  
  const nextRank = RANK_ORDER[currentIndex + 1];
  const nextThreshold = RANK_THRESHOLDS[nextRank];
  const currentThreshold = RANK_THRESHOLDS[currentRank];
  
  const tasksInCurrentRank = currentThreshold.max - currentThreshold.min + 1;
  const tasksCompleted = completedTasks - currentThreshold.min;
  const progress = Math.min(100, (tasksCompleted / tasksInCurrentRank) * 100);
  
  return {
    currentRank,
    nextRank,
    progress: Math.round(progress),
    tasksToNext: nextThreshold.min - completedTasks,
    isMaxRank: false
  };
}

module.exports = {
  RANKS,
  RANK_THRESHOLDS,
  RANK_ORDER,
  calculateRank,
  checkRankUpgrade,
  getRankProgress
};
