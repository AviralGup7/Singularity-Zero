import * as React from "react"

import { cn } from "@/lib/utils"

const Slider = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    defaultValue?: number[]
    value?: number[]
    min?: number
    max?: number
    step?: number
    disabled?: boolean
    orientation?: "horizontal" | "vertical"
  }
>(({ className, defaultValue, value, min = 0, max = 100, step = 1, disabled, orientation = "horizontal", ...props }, ref) => {
  const currentValues = value ?? defaultValue ?? [0]
  const percentage = ((currentValues[0] - min) / (max - min)) * 100

  return (
    <div
      ref={ref}
      className={cn(
        "relative flex w-full touch-none select-none items-center",
        className
      )}
      role="slider"
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={currentValues[0]}
      aria-disabled={disabled}
      aria-orientation={orientation}
      tabIndex={disabled ? undefined : 0}
      {...props}
    >
      <div className="relative h-2 w-full grow overflow-hidden rounded-full bg-secondary">
        <div
          className="absolute h-full bg-primary"
          style={{ width: `${percentage}%` }}
        />
      </div>
      <div
        className="block h-5 w-5 rounded-full border-2 border-primary bg-background ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
        style={{ position: "absolute", left: `calc(${percentage}% - 10px)` }}
      />
    </div>
  )
})
Slider.displayName = "Slider"

export { Slider }
