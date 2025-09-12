/**
 * CloudQuery Logo Component
 */
import React from "react";

interface CloudQueryLogoProps {
  className?: string;
  size?: "sm" | "md" | "lg";
  showText?: boolean;
}

export const CloudQueryLogo: React.FC<CloudQueryLogoProps> = ({
  className = "",
  size = "md",
  showText = true,
}) => {
  const textSizeClasses = {
    sm: "text-sm",
    md: "text-lg",
    lg: "text-2xl",
  };

  const iconSizeClasses = {
    sm: "h-6 w-6",
    md: "h-8 w-8",
    lg: "h-12 w-12",
  };

  return null;
};

export default CloudQueryLogo;
