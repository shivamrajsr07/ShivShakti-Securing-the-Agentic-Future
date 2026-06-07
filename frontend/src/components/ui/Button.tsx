import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "../../lib/utils";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger";
  icon?: ReactNode;
};

export function Button({ className, variant = "primary", icon, children, ...props }: ButtonProps) {
  const variants = {
    primary: "bg-signal text-ink shadow-[0_0_28px_rgba(37,208,162,0.22)] hover:bg-emerald-300",
    secondary: "border border-white/10 bg-white/[0.055] text-slate-100 hover:border-azure/40 hover:bg-white/[0.09]",
    danger: "bg-danger text-white shadow-[0_0_28px_rgba(255,95,102,0.22)] hover:bg-red-400"
  };
  return (
    <button
      className={cn(
        "inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className
      )}
      {...props}
    >
      {icon}
      {children}
    </button>
  );
}
