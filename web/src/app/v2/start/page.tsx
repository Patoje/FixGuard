import { TargetUrlEntry } from "./components/TargetUrlEntry";

export default function StartPage() {
  return (
    <main className="flex min-h-[70vh] flex-col items-center justify-center px-4">
      <div className="mb-6 text-center">
        <h1 className="text-lg font-semibold text-zinc-100">FixGuard</h1>
        <p className="mt-1 text-sm text-zinc-500">
          Authorized web security assessment
        </p>
      </div>
      <TargetUrlEntry />
    </main>
  );
}
