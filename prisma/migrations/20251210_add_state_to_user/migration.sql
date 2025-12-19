-- Add required state column to users for Venezuelan segmentation
ALTER TABLE "User" ADD COLUMN "state" TEXT NOT NULL DEFAULT 'DESCONOCIDO';
