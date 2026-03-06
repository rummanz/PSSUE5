"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { RefreshCcw, Upload, Play, Square } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import { toast } from "sonner"
import axios from "axios"
import { Area, AreaChart, CartesianGrid, Legend, Tooltip, XAxis } from "recharts"
import {
  ChartContainer,
  type ChartConfig,
} from "@/components/ui/chart"

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

interface ServerStatus {
  address: string
  port: number
  ready: boolean
  numConnectedClients: number
  lastPingReceived: number
  version?: string
  pid?: number | null
  is_running?: boolean
  stats?: {
    total_sessions: number
    total_duration_seconds: number
    average_session_duration_seconds: number
  }
}

interface StatusResponse {
  servers: ServerStatus[]
}

interface TimelinePoint {
  date: string
  total_sessions: number
  total_duration_seconds: number
  total_duration_minutes: number
  average_session_duration_seconds: number
}

type TimeRange = "90d" | "30d" | "7d"

const chartConfig = {
  sessions: {
    label: "Sessions",
    color: "var(--chart-1)",
  },
  duration: {
    label: "Avg Duration (min)",
    color: "var(--chart-2)",
  },
} satisfies ChartConfig

export default function Dashboard() {
  const [servers, setServers] = useState<ServerStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [serverActionLoading, setServerActionLoading] = useState<Record<string, boolean>>({})
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadStage, setUploadStage] = useState<"idle" | "uploading" | "processing">("idle")
  const [timeRange, setTimeRange] = useState<TimeRange>("30d")
  const [timelineData, setTimelineData] = useState<TimelinePoint[]>([])
  const [file, setFile] = useState<File | null>(null)
  const processingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopProcessingProgress = () => {
    if (processingIntervalRef.current) {
      clearInterval(processingIntervalRef.current)
      processingIntervalRef.current = null
    }
  }

  const startProcessingProgress = () => {
    setUploadStage("processing")
    setUploadProgress((prev) => (prev < 60 ? 60 : prev))
    stopProcessingProgress()
    processingIntervalRef.current = setInterval(() => {
      setUploadProgress((prev) => (prev < 95 ? prev + 1 : prev))
    }, 500)
  }

  const fetchLiveData = async () => {
    try {
      setLoading(true)
      const statusRes = await fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/status`)

      if (statusRes.ok) {
        const statusData: StatusResponse = await statusRes.json()
        setServers(statusData.servers || [])
        setLastUpdated(new Date())
      } else {
        console.error("Failed to fetch status")
      }
    } catch (error) {
      console.error("Error fetching status:", error)
    } finally {
      setLoading(false)
    }
  }

  const fetchTimelineData = async () => {
    try {
      const timelineRes = await fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/stats/timeline`)
      if (!timelineRes.ok) {
        setTimelineData([])
        return
      }

      const tData = await timelineRes.json()
      const timelineResults = tData.results || []

      const aggregateByDate = new Map<string, { total_sessions: number; total_duration_seconds: number }>()

      for (const result of timelineResults) {
        if (result.status !== "success" || !result.data?.timeline) continue

        for (const point of result.data.timeline) {
          if (!point?.date) continue

          const existing = aggregateByDate.get(point.date) || {
            total_sessions: 0,
            total_duration_seconds: 0
          }

          existing.total_sessions += Number(point.total_sessions || 0)
          existing.total_duration_seconds += Number(point.total_duration_seconds || 0)
          aggregateByDate.set(point.date, existing)
        }
      }

      const aggregatedTimeline: TimelinePoint[] = Array.from(aggregateByDate.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([date, values]) => ({
          date,
          total_sessions: values.total_sessions,
          total_duration_seconds: values.total_duration_seconds,
          total_duration_minutes: values.total_duration_seconds / 60,
          average_session_duration_seconds:
            values.total_sessions > 0 ? values.total_duration_seconds / values.total_sessions : 0
        }))

      setTimelineData(aggregatedTimeline)
    } catch {
      setTimelineData([])
    }
  }

  // Stats aggregation
  const totalSessions = servers.reduce((acc, s) => acc + (s.stats?.total_sessions || 0), 0);
  const globalTotalDuration = servers.reduce((acc, s) => acc + (s.stats?.total_duration_seconds || 0), 0);
  const globalAvgDuration = totalSessions > 0 ? globalTotalDuration / totalSessions : 0;

  const filteredData = useMemo(() => {
    const days = timeRange === "90d" ? 90 : timeRange === "30d" ? 30 : 7
    const cutoff = new Date()
    cutoff.setDate(cutoff.getDate() - days)

    return timelineData
      .filter((point) => new Date(point.date) >= cutoff)
      .map((point) => ({
        date: point.date,
        sessions: point.total_sessions,
        duration: Number((point.average_session_duration_seconds / 60).toFixed(1)),
      }))
  }, [timelineData, timeRange])


  const handleUpload = async () => {
    if (!file) {
      toast.error("Please select a file first")
      return
    }

    try {
      setUploading(true)
      setUploadProgress(0)
      setUploadStage("uploading")
      const formData = new FormData()
      formData.append("file", file)

      const response = await axios.post(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/upload`, formData, {
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total)
            const mappedUploadProgress = Math.min(60, Math.round(percentCompleted * 0.6))
            setUploadProgress(mappedUploadProgress)
            if (percentCompleted >= 100 && uploadStage !== "processing") {
              startProcessingProgress()
            }
          }
        }
      })

      stopProcessingProgress()
      setUploadProgress(100)

      if (response.status === 200) {
        const results = response.data.results || []
        const successCount = results.filter((r: any) => r.status === "success").length
        const failedCount = results.filter((r: any) => r.status === "failed").length

        toast.success("Upload broadcasted successfully", {
          description: `Completed: ${successCount} success, ${failedCount} failed`,
        })
      } else {
        toast.error("Upload failed")
      }
    } catch (error) {
      toast.error("Error during upload", { description: error instanceof Error ? error.message : "Possible zip validation failure" })
      console.error(error)
    } finally {
      stopProcessingProgress()
      setUploading(false)
      setUploadStage("idle")
      setTimeout(() => setUploadProgress(0), 500)
    }
  }

  useEffect(() => {
    return () => {
      stopProcessingProgress()
    }
  }, [])

  const getServerKey = (server: ServerStatus) => `${server.address}:${server.port}`

  const handleServerCommand = async (server: ServerStatus, command: "start" | "stop") => {
    const key = getServerKey(server)

    try {
      setServerActionLoading((prev) => ({ ...prev, [key]: true }))

      const response = await fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/server/${encodeURIComponent(server.address)}/${command}`, {
        method: "POST",
      })

      if (response.ok) {
        toast.success(`${command === "start" ? "Start" : "Stop"} sent`, {
          description: `${server.address}:${server.port}`
        })
        fetchLiveData() // Update UI immediately
      } else {
        const errorData = await response.json().catch(() => ({}))
        toast.error(`Failed to ${command} ${server.address}`, {
          description: errorData?.error || "Request failed"
        })
      }
    } catch {
      toast.error(`Error sending ${command} to ${server.address}`)
    } finally {
      setServerActionLoading((prev) => ({ ...prev, [key]: false }))
    }
  }

  useEffect(() => {
    fetchTimelineData()
  }, [])

  useEffect(() => {
    fetchLiveData()
    const interval = setInterval(fetchLiveData, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="container mx-auto py-10 space-y-8">

      {/* Server Status Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Matchmaker Dashboard</CardTitle>
              <CardDescription>Real-time status of Pixel Streaming servers.</CardDescription>
            </div>
            <div className="flex items-center gap-4">
              {lastUpdated && (
                <span className="text-sm text-muted-foreground">
                  Updated: {lastUpdated.toLocaleTimeString()}
                </span>
              )}
              <Button variant="outline" size="icon" onClick={fetchLiveData} disabled={loading}>
                <RefreshCcw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address</TableHead>
                  <TableHead>Port</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Connected Players</TableHead>
                  <TableHead>Game Process</TableHead>
                  <TableHead>Sessions</TableHead>
                  <TableHead>Avg Duration</TableHead>
                  <TableHead>Control</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {servers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="h-24 text-center">
                      No servers connected.
                    </TableCell>
                  </TableRow>
                ) : (
                  servers.map((server, index) => (
                    <TableRow key={`${server.address}-${server.port}-${index}`}>
                      <TableCell className="font-medium">{server.address}</TableCell>
                      <TableCell>{server.port}</TableCell>
                      <TableCell>
                        <Badge variant={server.ready ? "default" : "destructive"}>
                          {server.ready ? "Ready" : "Busy"}
                        </Badge>
                      </TableCell>
                      <TableCell>{server.numConnectedClients}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Badge variant={server.is_running ? "outline" : "destructive"} className={server.is_running ? "border-green-500 text-green-500" : ""}>
                            {server.is_running ? "Running" : "Stopped"}
                          </Badge>
                          {server.pid && <span className="font-mono text-xs">PID: {server.pid}</span>}
                        </div>
                      </TableCell>
                      <TableCell>{server.stats?.total_sessions || 0}</TableCell>
                      <TableCell>{(server.stats?.average_session_duration_seconds || 0).toFixed(0)}s</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant={server.is_running ? "destructive" : "default"}
                          disabled={!!serverActionLoading[getServerKey(server)]}
                          onClick={() => handleServerCommand(server, server.is_running ? "stop" : "start")}
                        >
                          {serverActionLoading[getServerKey(server)] ? (
                            <RefreshCcw className="h-4 w-4 animate-spin" />
                          ) : server.is_running ? (
                            <>
                              <Square className="h-4 w-4 mr-2" /> Stop
                            </>
                          ) : (
                            <>
                              <Play className="h-4 w-4 mr-2" /> Start
                            </>
                          )}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Game Management Section */}
      <Card>
        <CardHeader>
          <CardTitle>Game Management</CardTitle>
          <CardDescription>Upload builds to all connected servers.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-1">
            <div className="space-y-4">
              <Label htmlFor="game-build">Upload Game Build (.zip)</Label>
              <div className="flex gap-2">
                <Input
                  id="game-build"
                  type="file"
                  accept=".zip"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                />
                <Button onClick={handleUpload} disabled={uploading}>
                  {uploading ? (
                    <span className="flex items-center">
                      <RefreshCcw className="h-4 w-4 mr-2 animate-spin" /> {uploadProgress}%
                    </span>
                  ) : (
                    <>
                      <Upload className="h-4 w-4 mr-2" /> Upload
                    </>
                  )}
                </Button>
              </div>
              {uploading && (
                <>
                  <Progress value={uploadProgress} className="w-full h-2" />
                  <p className="text-xs text-muted-foreground">
                    {uploadStage === "uploading"
                      ? "Uploading build to Matchmaker..."
                      : uploadStage === "processing"
                        ? "Transferring build to game servers and extracting..."
                        : "Preparing upload..."}
                  </p>
                </>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats Section */}
      <Card>
        <CardHeader>
          <CardTitle>Game Statistics (Lifetime)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            <div className="flex flex-col">
              <span className="text-sm text-muted-foreground">Total Sessions Played</span>
              <span className="text-2xl font-bold">{totalSessions}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-sm text-muted-foreground">Avg Session Duration</span>
              <span className="text-2xl font-bold">{globalAvgDuration.toFixed(1)}s</span>
            </div>
            <div className="flex flex-col">
              <span className="text-sm text-muted-foreground">Total Playtime</span>
              <span className="text-2xl font-bold">{(globalTotalDuration / 3600).toFixed(2)} hrs</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="pt-0">
        <CardHeader className="flex items-center gap-2 space-y-0 border-b py-5 sm:flex-row">
          <div className="grid flex-1 gap-1">
            <CardTitle>Area Chart - Interactive</CardTitle>
            <CardDescription>
              Showing sessions and average duration for the selected range
            </CardDescription>
          </div>
          <Select value={timeRange} onValueChange={(value) => setTimeRange(value as TimeRange)}>
            <SelectTrigger
              className="w-[160px] rounded-lg sm:ml-auto"
              aria-label="Select a value"
            >
              <SelectValue placeholder="Last 30 days" />
            </SelectTrigger>
            <SelectContent className="rounded-xl">
              <SelectItem value="90d" className="rounded-lg">Last 3 months</SelectItem>
              <SelectItem value="30d" className="rounded-lg">Last 30 days</SelectItem>
              <SelectItem value="7d" className="rounded-lg">Last 7 days</SelectItem>
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
          {filteredData.length === 0 ? (
            <p className="text-sm text-muted-foreground">No timeline data available yet.</p>
          ) : (
            <ChartContainer
              config={chartConfig}
              className="aspect-auto h-[250px] w-full"
            >
              <AreaChart data={filteredData}>
                <defs>
                  <linearGradient id="fillSessions" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-sessions)" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="var(--color-sessions)" stopOpacity={0.1} />
                  </linearGradient>
                  <linearGradient id="fillDuration" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-duration)" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="var(--color-duration)" stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} />
                <XAxis
                  dataKey="date"
                  tickLine={false}
                  axisLine={false}
                  tickMargin={8}
                  minTickGap={32}
                  tickFormatter={(value) => {
                    const date = new Date(value)
                    return date.toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  }}
                />
                <Tooltip
                  cursor={false}
                  labelFormatter={(value) => {
                    return new Date(value).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  }}
                  formatter={(value, name) => {
                    if (name === "duration") return [`${Number(value).toFixed(1)} min`, "Avg Duration"]
                    return [Number(value).toLocaleString(), "Sessions"]
                  }}
                  contentStyle={{ borderRadius: 12 }}
                />
                <Area
                  dataKey="duration"
                  type="natural"
                  fill="url(#fillDuration)"
                  stroke="var(--color-duration)"
                  fillOpacity={0.55}
                  strokeWidth={2}
                />
                <Area
                  dataKey="sessions"
                  type="natural"
                  fill="url(#fillSessions)"
                  stroke="var(--color-sessions)"
                  fillOpacity={0.45}
                  strokeWidth={2}
                />
                <Legend />
              </AreaChart>
            </ChartContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Servers</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{servers.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Players</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {servers.reduce((acc, server) => acc + server.numConnectedClients, 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Available Capacity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {servers.filter(s => s.ready).length}
            </div>
            <p className="text-xs text-muted-foreground">
              Servers ready to accept new connections
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
