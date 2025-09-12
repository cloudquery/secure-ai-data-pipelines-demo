/**
 * Reusable Card component
 */
import React from "react";
import { clsx } from "clsx";

interface CardProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
  subtitle?: string;
  padding?: "none" | "small" | "medium" | "large";
  shadow?: "none" | "small" | "medium" | "large";
  border?: boolean;
  hover?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  className,
  title,
  subtitle,
  padding = "medium",
  shadow = "small",
  border = true,
  hover = false,
}) => {
  const paddingClasses = {
    none: "",
    small: "p-3",
    medium: "p-6",
    large: "p-8",
  };

  const shadowClasses = {
    none: "",
    small: "shadow-sm",
    medium: "shadow-md",
    large: "shadow-lg",
  };

  return (
    <div
      className={clsx(
        "bg-cloudquery-bgGradient rounded-lg",
        paddingClasses[padding],
        shadowClasses[shadow],
        border && "border border-cloudquery-logoGreen/20",
        hover && "hover:shadow-md transition-shadow duration-200",
        className
      )}
    >
      {(title || subtitle) && (
        <div className="mb-4">
          {title && (
            <h3 className="text-lg font-semibold text-brand-white mb-1">
              {title}
            </h3>
          )}
          {subtitle && (
            <p className="text-sm text-cloudquery-textWhite/80">{subtitle}</p>
          )}
        </div>
      )}
      {children}
    </div>
  );
};

export default Card;
