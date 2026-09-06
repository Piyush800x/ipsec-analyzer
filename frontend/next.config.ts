import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Ships the server plus only the traced dependencies, so the runtime image
  // in docker-compose.offline.yml does not carry a full node_modules tree.
  // Dockerfile's runtime stage depends on this being set.
  output: "standalone",
};

export default nextConfig;
