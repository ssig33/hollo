import "../src/logging";
import db from "../src/db";
import { eq } from "drizzle-orm";
import { posts } from "../src/schema";
import { formatText } from "../src/text";

const reRenderPosts = async () => {
  const owners = await db.query.accountOwners.findMany({
    with: { account: true },
  });

  for (const owner of owners) {
    const postList = await db.query.posts.findMany({
      where: eq(posts.accountId, owner.id),
    });

    /*const fmtOpts = {
      url: fedCtx.url,
      contextLoader: fedCtx.contextLoader,
      documentLoader: await fedCtx.getDocumentLoader({
        username: account.handle,
      }),
    };*/


    let i = 0;
    for (const post of postList) {
      i++;
      console.log(post);
      console.log("Rendering post", i, "of", postList.length);
    }
  }
};

await reRenderPosts();

process.exit();
