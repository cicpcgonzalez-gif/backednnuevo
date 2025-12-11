const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

class SecurityLogger {
  
  /**
   * Log a security event
   * @param {object} params
   * @param {string} params.action - The action performed (e.g., 'LOGIN_SUCCESS', 'PASSWORD_CHANGE')
   * @param {string} params.userEmail - Email of the user (if known)
   * @param {number} [params.userId] - ID of the user (if known)
   * @param {string} [params.ipAddress] - IP Address of the request
   * @param {string} [params.userAgent] - User Agent of the request
   * @param {string} [params.severity='INFO'] - INFO, WARN, ERROR, CRITICAL
   * @param {string} [params.detail] - Human readable detail
   * @param {object} [params.metadata] - Additional structured data
   * @param {string} [params.entity] - Affected entity (e.g., 'User', 'Raffle')
   * @param {string} [params.entityId] - ID of the affected entity
   */
  async log({ action, userEmail, userId, ipAddress, userAgent, severity = 'INFO', detail, metadata = {}, entity, entityId }) {
    try {
      // Sanitize metadata to remove sensitive fields like passwords
      const sanitizedMetadata = this._sanitize(metadata);

      await prisma.auditLog.create({
        data: {
          action,
          userEmail,
          userId,
          ipAddress,
          userAgent,
          severity,
          detail,
          metadata: sanitizedMetadata,
          entity,
          entityId: entityId ? String(entityId) : null
        }
      });

      // If critical, we might want to alert immediately (console for now)
      if (severity === 'CRITICAL') {
        console.error(`[SECURITY CRITICAL] ${action} by ${userEmail || 'unknown'} from ${ipAddress}`);
      }

    } catch (error) {
      console.error('Failed to write security log:', error);
      // Fail safe: don't crash the app if logging fails
    }
  }

  _sanitize(obj) {
    if (!obj) return {};
    const sensitiveKeys = ['password', 'token', 'secret', 'creditCard', 'cvv'];
    const newObj = { ...obj };
    
    for (const key in newObj) {
      if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
        newObj[key] = '[REDACTED]';
      } else if (typeof newObj[key] === 'object' && newObj[key] !== null) {
        newObj[key] = this._sanitize(newObj[key]);
      }
    }
    return newObj;
  }
}

module.exports = new SecurityLogger();
