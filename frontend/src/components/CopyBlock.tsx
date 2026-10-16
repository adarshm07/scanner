import { useState } from "react";

/** A labelled code block with a copy button. `copyText` defaults to the shown text. */
export function CopyBlock({
  label,
  text,
  copyText,
}: {
  label: string;
  text: string;
  copyText?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(copyText ?? text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can be blocked (http, iframe); the text is still selectable.
    }
  }

  return (
    <figure className="m-0 border border-line bg-ink2">
      <figcaption className="flex items-center border-b border-line bg-panel px-3 py-1.5 text-[11.5px] text-muted">
        <span>{label}</span>
        <div className="grow" />
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${label}`}
          className="cursor-pointer rounded border border-edge bg-transparent px-2 py-0.5 text-[11.5px] text-text3 hover:border-edge-hover"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </figcaption>
      <pre className="m-0 overflow-x-auto p-3 font-mono text-[12px] leading-[1.7] text-text3">
        {text}
      </pre>
    </figure>
  );
}
