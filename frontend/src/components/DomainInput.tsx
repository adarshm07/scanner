interface DomainInputProps {
  mode: "repo" | "domain";
  value: string;
  onChange: (value: string) => void;
}

export function DomainInput({ mode, value, onChange }: DomainInputProps) {
  const isRepo = mode === "repo";
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-[13px] font-medium text-muted">
        {isRepo ? "Repository URL" : "Domain"}
      </label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={isRepo ? "https://github.com/org/repo" : "example.com"}
        className="h-10 w-full rounded border border-edge bg-ink2 px-3 font-mono text-[13.5px] text-ink3 outline-hidden placeholder:text-dim focus:border-muted"
      />
    </div>
  );
}
