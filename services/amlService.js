const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const securityLogger = require('./securityLogger');

class AMLService {
  
  /**
   * Check if a person is in the blacklist
   * @param {string} name 
   * @param {string} documentNumber 
   * @returns {Promise<{isBlacklisted: boolean, reason: string, source: string}>}
   */
  async checkPerson(name, documentNumber) {
    // 1. Check by Document Number (Exact Match)
    if (documentNumber) {
      const match = await prisma.blacklist.findUnique({
        where: { documentNumber }
      });
      
      if (match) {
        return {
          isBlacklisted: true,
          reason: match.reason,
          source: match.source
        };
      }
    }

    // 2. Check by Name (Fuzzy Match - Simplified for now)
    // In a real production system, use a fuzzy search library or database feature
    if (name) {
      const match = await prisma.blacklist.findFirst({
        where: {
          name: {
            equals: name,
            mode: 'insensitive'
          }
        }
      });

      if (match) {
        return {
          isBlacklisted: true,
          reason: match.reason,
          source: match.source
        };
      }
    }

    return { isBlacklisted: false };
  }

  /**
   * Add a person to the internal blacklist
   */
  async addToBlacklist(name, documentNumber, reason, source = 'INTERNAL', adminUserId) {
    try {
      const entry = await prisma.blacklist.create({
        data: {
          name,
          documentNumber,
          reason,
          source
        }
      });

      await securityLogger.log({
        action: 'BLACKLIST_ADD',
        userId: adminUserId,
        severity: 'WARN',
        detail: `Added ${name} (${documentNumber}) to blacklist. Reason: ${reason}`,
        entity: 'Blacklist',
        entityId: entry.id
      });

      return entry;
    } catch (error) {
      console.error('Error adding to blacklist:', error);
      throw error;
    }
  }
}

module.exports = new AMLService();
