"use client"

import * as React from "react"
import * as RechartsPrimitive from "recharts"

import { cn } from "@/lib/utils"

export type ChartConfig = {
  [k: string]: {
    label?: React.ReactNode
    color?: string
  }
}

type ChartContextProps = {
  config: ChartConfig
}

const ChartContext = React.createContext<ChartContextProps | null>(null)

function useChart() {
  const context = React.useContext(ChartContext)

  if (!context) {
    throw new Error("useChart must be used within a <ChartContainer />")
  }

  return context
}

function ChartContainer({
  id,
  className,
  children,
  config,
  ...props
}: React.ComponentProps<"div"> & {
  config: ChartConfig
  children: React.ComponentProps<typeof RechartsPrimitive.ResponsiveContainer>["children"]
}) {
  const uniqueId = React.useId()
  const chartId = `chart-${id || uniqueId.replace(/:/g, "")}`

  return (
    <ChartContext.Provider value={{ config }}>
      <div
        data-slot="chart"
        data-chart={chartId}
        className={cn(
          "[&_.recharts-cartesian-axis-tick_text]:fill-muted-foreground [&_.recharts-cartesian-grid_line[stroke='#ccc']]:stroke-border/50 [&_.recharts-curve.recharts-tooltip-cursor]:stroke-border [&_.recharts-dot[stroke='#fff']]:stroke-transparent [&_.recharts-layer]:outline-none [&_.recharts-polar-grid_[stroke='#ccc']]:stroke-border [&_.recharts-radial-bar-background-sector]:fill-muted [&_.recharts-reference-line_[stroke='#ccc']]:stroke-border [&_.recharts-sector[stroke='#fff']]:stroke-transparent [&_.recharts-sector]:outline-none [&_.recharts-surface]:outline-none",
          className
        )}
        {...props}
      >
        <ChartStyle id={chartId} config={config} />
        <RechartsPrimitive.ResponsiveContainer>
          {children}
        </RechartsPrimitive.ResponsiveContainer>
      </div>
    </ChartContext.Provider>
  )
}

function ChartStyle({ id, config }: { id: string; config: ChartConfig }) {
  const colorConfig = Object.entries(config).filter(([, cfg]) => cfg.color)

  if (!colorConfig.length) {
    return null
  }

  return (
    <style
      dangerouslySetInnerHTML={{
        __html: `
[data-chart=${id}] {
${colorConfig
  .map(([key, cfg]) => `  --color-${key}: ${cfg.color};`)
  .join("\n")}
}
`,
      }}
    />
  )
}

function ChartTooltip(
  props: React.ComponentProps<typeof RechartsPrimitive.Tooltip>
) {
  return <RechartsPrimitive.Tooltip {...props} />
}

function ChartTooltipContent({
  active,
  payload,
  className,
  indicator = "dot",
  hideLabel = false,
  label,
  labelFormatter,
  formatter,
  color,
}: React.ComponentProps<"div"> &
  Pick<RechartsPrimitive.TooltipProps<number, string>, "active" | "payload" | "label" | "formatter" | "labelFormatter"> & {
    hideLabel?: boolean
    indicator?: "line" | "dot"
    color?: string
  }) {
  const { config } = useChart()

  if (!active || !payload?.length) {
    return null
  }

  const tooltipLabel = !hideLabel
    ? labelFormatter
      ? labelFormatter(label, payload)
      : label
    : null

  return (
    <div className={cn("bg-background/95 border-border/50 grid min-w-[8rem] gap-1 rounded-lg border px-2.5 py-1.5 text-xs shadow-xl", className)}>
      {tooltipLabel ? <div className="font-medium">{tooltipLabel}</div> : null}
      <div className="grid gap-1">
        {payload.map((item, index) => {
          const key = item.dataKey?.toString() ?? item.name?.toString() ?? `item-${index}`
          const itemConfig = config[key]
          const itemColor = color || item.color || `var(--color-${key})`

          return (
            <div key={key} className="flex items-center gap-2">
              {indicator === "dot" ? (
                <span className="size-2 rounded-[2px]" style={{ backgroundColor: itemColor }} />
              ) : (
                <span className="h-0.5 w-3" style={{ backgroundColor: itemColor }} />
              )}
              <span className="text-muted-foreground">{itemConfig?.label || item.name}</span>
              <span className="ml-auto font-mono font-medium text-foreground">
                {formatter && item.value !== undefined
                  ? formatter(item.value, item.name ?? key, item, index, payload)
                  : item.value?.toLocaleString?.() ?? "—"}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ChartLegend(
  props: RechartsPrimitive.LegendProps
) {
  const LegendComponent = RechartsPrimitive.Legend as React.ComponentType<RechartsPrimitive.LegendProps>
  return <LegendComponent {...props} />
}

function ChartLegendContent({
  className,
  payload,
}: React.ComponentProps<"div"> &
  Pick<RechartsPrimitive.LegendProps, "payload">) {
  const { config } = useChart()

  if (!payload?.length) {
    return null
  }

  return (
    <div className={cn("flex items-center justify-center gap-4", className)}>
      {payload.map((item) => {
        const key = item.dataKey?.toString() ?? ""
        const itemConfig = config[key]
        return (
          <div key={key} className="flex items-center gap-1.5">
            <span className="size-2 rounded-[2px]" style={{ backgroundColor: item.color }} />
            <span className="text-muted-foreground text-sm">{itemConfig?.label || item.value}</span>
          </div>
        )
      })}
    </div>
  )
}

export {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartStyle,
  ChartTooltip,
  ChartTooltipContent,
}
