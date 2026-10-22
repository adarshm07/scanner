import type { ReactNode } from "react";

export type PageId = "dashboard" | "users" | "apps" | "findings" | "scans" | "scan";

const NAV: { section: string; items: { id: PageId; label: string; icon: ReactNode }[] }[] = [
  {
    section: "Access review",
    items: [
      { id: "dashboard", label: "Dashboard", icon: <IconGrid /> },
      { id: "users", label: "Users", icon: <IconUsers /> },
      { id: "apps", label: "Apps", icon: <IconApps /> },
      { id: "findings", label: "Findings", icon: <IconFlag /> },
      { id: "scans", label: "Scheduled scans", icon: <IconClock /> },
    ],
  },
  {
    section: "Code security",
    items: [{ id: "scan", label: "Code & domain scan", icon: <IconScan /> }],
  },
];

/** Sidebar layout shared by every page. Collapses to a top bar on narrow screens. */
export function AppShell({
  page,
  footer,
  badges = {},
  children,
}: {
  page: PageId;
  footer?: ReactNode;
  badges?: Partial<Record<PageId, number>>;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen bg-ink text-ink3 lg:grid lg:grid-cols-[224px_minmax(0,1fr)]">
      <aside className="sticky top-0 z-10 flex flex-col border-b border-line bg-ink2 lg:h-screen lg:border-r lg:border-b-0">
        <div className="flex h-[52px] shrink-0 items-center gap-2 px-4 lg:border-b lg:border-line">
          <span className="grid h-6 w-6 place-items-center rounded-[4px] bg-ink3 font-mono text-[12px] font-bold text-ink">X</span>
          <span className="text-[15px] font-semibold tracking-[-0.01em]">Scanner-X</span>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-2 lg:flex-1 lg:flex-col lg:gap-5 lg:overflow-visible lg:py-4">
          {NAV.map((group) => (
            <div key={group.section} className="flex gap-1 lg:flex-col lg:gap-0.5">
              <div className="hidden px-2 pb-1 text-[11px] font-medium uppercase tracking-wide text-dim lg:block">{group.section}</div>
              {group.items.map((item) => {
                const active = page === item.id;
                const badge = badges[item.id];
                return (
                  <a
                    key={item.id}
                    href={`#${item.id}`}
                    aria-current={active ? "page" : undefined}
                    className={`flex shrink-0 items-center gap-2.5 whitespace-nowrap rounded-[4px] px-2 py-1.5 text-[13px] no-underline ${
                      active ? "bg-panel2 font-medium text-ink3 shadow-[inset_2px_0_0_#3987e5]" : "text-text3 hover:bg-hover hover:text-ink3"
                    }`}
                  >
                    <span className={active ? "text-ink3" : "text-muted"}>{item.icon}</span>
                    {item.label}
                    {badge != null && badge > 0 && (
                      <span className="ml-auto rounded-full bg-[#7a6420]/30 px-1.5 font-mono text-[11px] text-[#e8c45a]">{badge}</span>
                    )}
                  </a>
                );
              })}
            </div>
          ))}
        </nav>
        {footer && <div className="hidden border-t border-line px-4 py-3 font-mono text-[11px] leading-relaxed text-dim lg:block">{footer}</div>}
      </aside>
      <main className="min-w-0">{children}</main>
    </div>
  );
}

const svg = { width: 16, height: 16, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };

function IconGrid() {
  return (
    <svg {...svg}>
      <rect x="2" y="2" width="5" height="5" rx="1" />
      <rect x="9" y="2" width="5" height="5" rx="1" />
      <rect x="2" y="9" width="5" height="5" rx="1" />
      <rect x="9" y="9" width="5" height="5" rx="1" />
    </svg>
  );
}
function IconUsers() {
  return (
    <svg {...svg}>
      <circle cx="6" cy="5.5" r="2.5" />
      <path d="M1.5 13.5c.6-2.4 2.3-3.5 4.5-3.5s3.9 1.1 4.5 3.5" />
      <path d="M10.5 3.2a2.5 2.5 0 0 1 0 4.6M12 10.2c1.3.4 2.1 1.5 2.5 3.3" />
    </svg>
  );
}
function IconApps() {
  return (
    <svg {...svg}>
      <rect x="2" y="3" width="12" height="10" rx="1.5" />
      <path d="M2 6h12M4.5 4.5h0M6.5 4.5h0" />
    </svg>
  );
}
function IconFlag() {
  return (
    <svg {...svg}>
      <path d="M3 14V2.5M3 3h8.5l-1.8 3 1.8 3H3" />
    </svg>
  );
}
function IconClock() {
  return (
    <svg {...svg}>
      <circle cx="8" cy="8" r="6" />
      <path d="M8 4.5V8l2.5 1.5" />
    </svg>
  );
}
function IconScan() {
  return (
    <svg {...svg}>
      <path d="M2 5V3a1 1 0 0 1 1-1h2M11 2h2a1 1 0 0 1 1 1v2M14 11v2a1 1 0 0 1-1 1h-2M5 14H3a1 1 0 0 1-1-1v-2M4.5 8h7" />
    </svg>
  );
}
