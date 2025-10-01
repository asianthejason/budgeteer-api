/*
  Warnings:

  - A unique constraint covering the columns `[userId,externalId]` on the table `Account` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[userId,externalId]` on the table `InstitutionConnection` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[userId,externalId]` on the table `Transaction` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "Profile" ADD COLUMN     "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- CreateIndex
CREATE UNIQUE INDEX "Account_userId_externalId_key" ON "Account"("userId", "externalId");

-- CreateIndex
CREATE UNIQUE INDEX "InstitutionConnection_userId_externalId_key" ON "InstitutionConnection"("userId", "externalId");

-- CreateIndex
CREATE UNIQUE INDEX "Transaction_userId_externalId_key" ON "Transaction"("userId", "externalId");
