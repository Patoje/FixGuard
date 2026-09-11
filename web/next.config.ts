import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    const v2BackendUrl = process.env.V2_BACKEND_URL || "http://127.0.0.1:4000";
    return [
      {
        source: "/api/v2/:path*",
        destination: `${v2BackendUrl}/api/v2/:path*`,
      },
    ];
  },
};

export default nextConfig;
