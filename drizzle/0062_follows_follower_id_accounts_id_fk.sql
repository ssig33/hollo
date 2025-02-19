ALTER TABLE "follows" DROP CONSTRAINT "follows_follower_id_accounts_id_fk";
--> statement-breakpoint
DELETE FROM "follows" WHERE "follower_id" NOT IN (SELECT "id" FROM "accounts");
--> statement-breakpoint
ALTER TABLE "follows" ADD CONSTRAINT "follows_follower_id_accounts_id_fk" FOREIGN KEY ("follower_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;
