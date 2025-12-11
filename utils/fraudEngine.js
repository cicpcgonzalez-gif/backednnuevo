const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

/**
 * Fraud Detection Engine
 * Analyzes user actions for suspicious patterns.
 */
const FraudEngine = {
  
  /**
   * Log suspicious activity to DB
   */
  async logActivity(userId, action, reason, severity = 'MEDIUM', ipAddress = null, metadata = {}) {
    try {
      await prisma.suspiciousActivity.create({
        data: {
          userId,
          action,
          reason,
          severity,
          ipAddress,
          metadata
        }
      });

      // If severity is HIGH or CRITICAL, flag the user
      if (severity === 'HIGH' || severity === 'CRITICAL') {
        await prisma.user.update({
          where: { id: userId },
          data: { isFlagged: true, riskScore: { increment: severity === 'CRITICAL' ? 50 : 20 } }
        });
      } else {
        await prisma.user.update({
          where: { id: userId },
          data: { riskScore: { increment: 5 } }
        });
      }
      
      console.warn(`[FRAUD] Flagged user ${userId}: ${reason} (${severity})`);
    } catch (error) {
      console.error('Error logging suspicious activity:', error);
    }
  },

  /**
   * Check for high velocity ticket purchases
   * @param {number} userId 
   * @param {number} raffleId 
   */
  async checkPurchaseVelocity(userId, raffleId) {
    const TIME_WINDOW_MINUTES = 10;
    const TICKET_THRESHOLD = 50; // Max tickets in 10 mins without flag

    const tenMinutesAgo = new Date(Date.now() - TIME_WINDOW_MINUTES * 60 * 1000);
    
    const recentTickets = await prisma.ticket.count({
      where: {
        userId,
        raffleId,
        createdAt: { gte: tenMinutesAgo }
      }
    });

    if (recentTickets > TICKET_THRESHOLD) {
      return {
        isSuspicious: true,
        reason: `High velocity purchase: ${recentTickets} tickets in ${TIME_WINDOW_MINUTES} mins`,
        severity: 'HIGH'
      };
    }

    return { isSuspicious: false };
  },

  /**
   * Check for large transaction amounts
   * @param {number} amount 
   */
  checkTransactionAmount(amount) {
    const HIGH_AMOUNT_THRESHOLD = 1000; // Example threshold
    if (amount > HIGH_AMOUNT_THRESHOLD) {
      return {
        isSuspicious: true,
        reason: `Large transaction amount: ${amount}`,
        severity: 'MEDIUM'
      };
    }
    return { isSuspicious: false };
  },

  /**
   * Check for rapid login failures (Brute Force indicator)
   * This should be called after a failed login attempt
   */
  async checkLoginFailures(email, ipAddress) {
    // This would require querying AuditLog or a similar store if we logged failures there.
    // For now, we can rely on the rate limiter, but we could add DB logging here.
    return { isSuspicious: false };
  }
};

module.exports = FraudEngine;
