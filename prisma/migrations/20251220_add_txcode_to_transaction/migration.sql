-- Add txCode to Transaction for immutable, auditable transaction numbers

ALTER TABLE "Transaction" ADD COLUMN "txCode" TEXT;

CREATE UNIQUE INDEX "Transaction_txCode_key" ON "Transaction"("txCode");
