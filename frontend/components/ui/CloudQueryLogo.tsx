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
  const sizeClasses = {
    sm: "h-6 w-6",
    md: "h-8 w-8",
    lg: "h-12 w-12",
  };

  const textSizeClasses = {
    sm: "text-sm",
    md: "text-lg",
    lg: "text-2xl",
  };

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      {/* CloudQuery Logo SVG */}
      <svg
        className={sizeClasses[size]}
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Cloud icon */}
        <path
          d="M8 12C8 9.79086 9.79086 8 12 8H20C22.2091 8 24 9.79086 24 12V20C24 22.2091 22.2091 24 20 24H12C9.79086 24 8 22.2091 8 20V12Z"
          fill="#0ea5e9"
        />
        {/* Database/Query icon */}
        <path
          d="M12 10C10.8954 10 10 10.8954 10 12V20C10 21.1046 10.8954 22 12 22H20C21.1046 22 22 21.1046 22 20V12C22 10.8954 21.1046 10 20 10H12Z"
          fill="white"
        />
        {/* Query lines */}
        <path
          d="M14 14H18M14 16H18M14 18H16"
          stroke="#0ea5e9"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>

      {showText && (
        <span
          className={`font-bold text-cloudquery-darkBlue ${textSizeClasses[size]}`}
        >
          CloudQuery
        </span>
      )}
    </div>
  );
};

export default CloudQueryLogo;


