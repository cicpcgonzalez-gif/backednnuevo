const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const crypto = require('crypto');

const generateTxCode = () => `TX-${crypto.randomBytes(10).toString('hex').toUpperCase()}`;

// Mock implementation for external providers
const providers = {
  stripe: {
    createPaymentIntent: async (amount, currency) => {
      // In a real app, call Stripe API
      return {
        id: `pi_${crypto.randomBytes(12).toString('hex')}`,
        client_secret: `secret_${crypto.randomBytes(12).toString('hex')}`,
        status: 'pending'
      };
    },
    verifyPayment: async (externalId) => {
      // Mock verification
      return { status: 'succeeded', amount: 100, currency: 'usd' };
    }
  },
  binance: {
    createOrder: async (amount, currency) => {
      return {
        id: `ord_${crypto.randomBytes(12).toString('hex')}`,
        qr_code: 'https://binance.com/qr/mock',
        status: 'pending'
      };
    }
  }
};

class PaymentService {
  
  /**
   * Initiate a transaction
   * @param {number} userId 
   * @param {number} amount 
   * @param {string} currency 
   * @param {string} provider 
   * @param {string} type 
   * @param {number} raffleId 
   */
  async initiateTransaction(userId, amount, currency, provider, type, raffleId = null) {
    let externalData = {};
    let status = 'pending';

    try {
      if (provider === 'stripe') {
        externalData = await providers.stripe.createPaymentIntent(amount, currency);
      } else if (provider === 'binance') {
        externalData = await providers.binance.createOrder(amount, currency);
      } else if (provider === 'manual') {
        // Manual requires admin approval, starts as pending
        status = 'pending';
      }

      const transaction = await prisma.transaction.create({
        data: {
          txCode: generateTxCode(),
          userId,
          amount,
          currency,
          provider,
          type,
          status,
          raffleId,
          externalId: externalData.id || null,
          // For manual, reference might be added later by user
        }
      });

      return { transaction, externalData };
    } catch (error) {
      console.error('Payment initiation failed:', error);
      throw new Error('Payment initiation failed');
    }
  }

  /**
   * Handle Webhook or Callback from provider
   * @param {string} provider 
   * @param {object} data 
   */
  async handleWebhook(provider, data) {
    // This would parse the provider specific payload
    // For now, we assume we get an externalId and a status
    const { externalId, status } = data;

    const transaction = await prisma.transaction.findFirst({
      where: { externalId }
    });

    if (!transaction) {
      throw new Error('Transaction not found');
    }

    let newStatus = transaction.status;
    if (status === 'succeeded' || status === 'paid') {
      newStatus = 'approved';
    } else if (status === 'failed') {
      newStatus = 'failed';
    }

    if (newStatus !== transaction.status) {
      await prisma.transaction.update({
        where: { id: transaction.id },
        data: { 
          status: newStatus,
          reconciled: true,
          reconciledAt: new Date()
        }
      });
      
      // If approved, trigger any post-payment logic (e.g. issue tickets)
      // This might be handled by an event emitter in a larger app
    }

    return { success: true };
  }

  /**
   * Manual Reconciliation
   * @param {number} transactionId 
   * @param {string} status 
   * @param {string} adminNotes 
   */
  async reconcileManual(transactionId, status, adminNotes) {
    return await prisma.transaction.update({
      where: { id: transactionId },
      data: {
        status,
        reconciled: true,
        reconciledAt: new Date()
      }
    });
  }

  /**
   * Process a refund
   * @param {number} originalTransactionId 
   * @param {string} reason 
   */
  async processRefund(originalTransactionId, reason) {
    const originalTx = await prisma.transaction.findUnique({
      where: { id: originalTransactionId }
    });

    if (!originalTx || originalTx.status !== 'approved') {
      throw new Error('Transaction cannot be refunded');
    }

    // Create refund transaction
    const refundTx = await prisma.transaction.create({
      data: {
        txCode: generateTxCode(),
        userId: originalTx.userId,
        amount: originalTx.amount,
        currency: originalTx.currency,
        provider: originalTx.provider,
        type: 'refund',
        status: 'approved', // Assuming immediate approval for internal record
        raffleId: originalTx.raffleId,
        externalId: `ref_${crypto.randomBytes(8).toString('hex')}`,
        reconciled: true,
        reconciledAt: new Date()
      }
    });

    // Update original transaction status to refunded
    await prisma.transaction.update({
      where: { id: originalTx.id },
      data: { status: 'refunded' }
    });

    return refundTx;
  }
  
  /**
   * Get user balance (simple calculation)
   */
  async getUserBalance(userId) {
    const transactions = await prisma.transaction.findMany({
      where: { 
        userId, 
        status: 'approved' 
      }
    });
    
    // Sum deposits - withdrawals - purchases (if purchases deduct balance)
    // This logic depends on how purchases are handled (direct vs wallet)
    // Assuming direct purchase for now, but if we had a wallet:
    // return transactions.reduce((acc, tx) => {
    //   if (tx.type === 'deposit') return acc + tx.amount;
    //   if (tx.type === 'withdrawal') return acc - tx.amount;
    //   return acc;
    // }, 0);
    
    return 0; // Placeholder
  }
}

module.exports = new PaymentService();
