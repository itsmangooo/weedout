import type { NextConfig } from "next";

const legacyOrigin = process.env.LEGACY_WEB_URL ?? "http://legacy:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async rewrites() {
    return {
      beforeFiles: [],
      afterFiles: [],
      fallback: [
        {
          source: "/:path*",
          destination: `${legacyOrigin}/:path*`,
        },
      ],
    };
  },
};

export default nextConfig;
