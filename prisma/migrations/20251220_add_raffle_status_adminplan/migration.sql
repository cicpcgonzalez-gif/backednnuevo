-- Add missing fields used by the API code

-- 1) User.adminPlan
ALTER TABLE "User"
ADD COLUMN IF NOT EXISTS "adminPlan" JSONB;

-- 2) Raffle.status + lifecycle timestamps
ALTER TABLE "Raffle"
ADD COLUMN IF NOT EXISTS "status" TEXT NOT NULL DEFAULT 'active',
ADD COLUMN IF NOT EXISTS "activatedAt" TIMESTAMP(3),
ADD COLUMN IF NOT EXISTS "closedAt" TIMESTAMP(3);
