import * as React from "react"

export interface SafeResponsiveContainerProps {
  children: React.ReactNode
  width?: string | number
  height?: string | number
  minWidth?: string | number
  minHeight?: string | number
}

export const SafeResponsiveContainer = ({
  children,
  width = "100%",
  height = "100%",
  minWidth,
  minHeight,
}: SafeResponsiveContainerProps) => {
  const [dimensions, setDimensions] = React.useState<{ width: number; height: number } | null>(null)
  const containerRef = React.useRef<HTMLDivElement>(null)

  React.useEffect(() => {
    const element = containerRef.current
    if (!element) return

    // Check if the container already has dimensions on mount
    const rect = element.getBoundingClientRect()
    if (rect.width > 0 && rect.height > 0) {
      setDimensions({ width: rect.width, height: rect.height })
    } else {
      // Fallback if parent has no dimensions yet (e.g. before layout)
      setDimensions({ width: 600, height: 300 })
    }

    const observer = new ResizeObserver((entries) => {
      if (!entries || entries.length === 0) return
      const entry = entries[0]
      const { width: measuredWidth, height: measuredHeight } = entry.contentRect
      if (measuredWidth > 0 && measuredHeight > 0) {
        setDimensions({ width: measuredWidth, height: measuredHeight })
      }
    })

    observer.observe(element)
    return () => {
      observer.disconnect()
    }
  }, [])

  return (
    <div
      ref={containerRef}
      className="w-full h-full"
      style={{
        width: typeof width === "number" ? `${width}px` : width,
        height: typeof height === "number" ? `${height}px` : height,
        minWidth: typeof minWidth === "number" ? `${minWidth}px` : minWidth,
        minHeight: typeof minHeight === "number" ? `${minHeight}px` : minHeight,
      }}
    >
      {dimensions ? (
        typeof children === "function"
          ? (children as Function)(dimensions.width, dimensions.height)
          : React.isValidElement(children)
            ? React.cloneElement(children as React.ReactElement<any>, {
                width: dimensions.width,
                height: dimensions.height,
              })
            : children
      ) : null}
    </div>
  )
}
