/**
 * Reusable Badge component for status indicators
 */
import React from "react";
import { clsx } from "clsx";

interface BadgeProps {
  children: React.ReactNode;
  variant?:
    | "default"
    | "critical"
    | "high"
    | "medium"
    | "low"
    | "info"
    | "success"
    | "warning"
    | "error";
  size?: "sm" | "md" | "lg";
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = "default",
  size = "md",
  className,
}) => {
  const baseClasses = "inline-flex items-center font-medium rounded-full";

  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs",
    md: "px-2.5 py-1 text-sm",
    lg: "px-3 py-1.5 text-base",
  };

  const variantClasses = {
    default:
      "bg-cloudquery-logoGreen/20 text-cloudquery-textWhite border border-cloudquery-logoGreen/30",
    critical: "bg-red-500/20 text-red-300 border border-red-500/30",
    high: "bg-orange-500/20 text-orange-300 border border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30",
    low: "bg-green-500/20 text-green-300 border border-green-500/30",
    info: "bg-cloudquery-logoGreen/20 text-cloudquery-textWhite border border-cloudquery-logoGreen/30",
    success: "bg-green-500/20 text-green-300 border border-green-500/30",
    warning: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30",
    error: "bg-red-500/20 text-red-300 border border-red-500/30",
  };

  return (
    <span
      className={clsx(
        baseClasses,
        sizeClasses[size],
        variantClasses[variant],
        className
      )}
    >
      {children}
    </span>
  );
};

export default Badge;
