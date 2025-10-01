-- CreateTable
CREATE TABLE "UserCategoryRule" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "isRegex" BOOLEAN NOT NULL DEFAULT false,
    "category" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserCategoryRule_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "UserCategoryRule_userId_category_idx" ON "UserCategoryRule"("userId", "category");

-- CreateIndex
CREATE INDEX "UserCategoryRule_userId_pattern_idx" ON "UserCategoryRule"("userId", "pattern");

-- AddForeignKey
ALTER TABLE "UserCategoryRule" ADD CONSTRAINT "UserCategoryRule_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
