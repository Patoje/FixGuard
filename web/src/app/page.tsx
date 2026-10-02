import { redirect } from "next/navigation";

/**
 * Root entry used to be the V1 AGGRESSIVE scanner (localhost:4000 /api/scan).
 * FixGuard V2 is the only supported UI surface — send operators there.
 */
export default function Home() {
  redirect("/v2");
}
