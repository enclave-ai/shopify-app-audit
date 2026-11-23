import { shopifyApp, ApiVersion } from "@shopify/shopify-app-react-router/server";
import { PrismaSessionStorage } from "@shopify/shopify-app-session-storage-prisma";
import prisma from "./db.server";

const shopify = shopifyApp({
  apiKey: process.env.SHOPIFY_API_KEY,
  apiSecretKey: process.env.SHOPIFY_API_SECRET || "",
  apiVersion: ApiVersion.October26,
  sessionStorage: new PrismaSessionStorage(prisma),
  future: { expiringOfflineAccessTokens: true },
});

export default shopify;
