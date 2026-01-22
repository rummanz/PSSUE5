"use client"

import { useEffect, useState } from "react"
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
import { RefreshCcw, Upload, Play, Square, Info } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import { toast } from "sonner"
import axios from "axios"

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

export default function Dashboard() {
  const [servers, setServers] = useState<ServerStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [file, setFile] = useState<File | null>(null)

  const fetchData = async () => {
    try {
      setLoading(true)
      const [statusRes, versionRes, statsRes] = await Promise.all([
        fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/status`),
        fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/version`),
        fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/stats`) // This endpoint was added to matchmaker.js
      ]);

      if (statusRes.ok) {
        const statusData: StatusResponse = await statusRes.json()
        let updatedServers = statusData.servers;

        let versionResults: any[] = [];
        if (versionRes.ok) {
          const vData = await versionRes.json();
          versionResults = vData.results || [];
        }

        let statsResults: any[] = [];
        if (statsRes.ok) {
          const sData = await statsRes.json();
          statsResults = sData.results || [];
        }

        updatedServers = updatedServers.map((server: ServerStatus) => {
          const vInfo = versionResults.find((r: any) => r.ip === server.address);
          const sInfo = statsResults.find((r: any) => r.ip === server.address);

          return {
            ...server,
            version: vInfo?.data?.version || 'Unknown',
            pid: vInfo?.data?.pid || null,
            is_running: vInfo?.data?.is_running || false,
            stats: sInfo?.data || null
          };
        });

        setServers(updatedServers)
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

  // Calculate global states
  const allRunning = servers.length > 0 && servers.every(s => s.is_running);
  const allStopped = servers.length > 0 && servers.every(s => !s.is_running);

  // Stats aggregation
  const totalSessions = servers.reduce((acc, s) => acc + (s.stats?.total_sessions || 0), 0);
  const globalTotalDuration = servers.reduce((acc, s) => acc + (s.stats?.total_duration_seconds || 0), 0);
  const globalAvgDuration = totalSessions > 0 ? globalTotalDuration / totalSessions : 0;


  const handleUpload = async () => {
    if (!file) {
      toast.error("Please select a file first")
      return
    }

    try {
      setUploading(true)
      setUploadProgress(0)
      const formData = new FormData()
      formData.append("file", file)

      const response = await axios.post(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/upload`, formData, {
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total)
            setUploadProgress(percentCompleted)
          }
        }
      })

      if (response.status === 200) {
        toast.success("Upload broadcasted successfully", {
          description: `Sent to ${response.data.results.length} servers`,
        })
      } else {
        toast.error("Upload failed")
      }
    } catch (error) {
      toast.error("Error during upload", { description: error instanceof Error ? error.message : "Possible zip validation failure" })
      console.error(error)
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }

  const handleCommand = async (command: "start" | "stop") => {
    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_MATCHMAKER_URL}/api/game/broadcast`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command }),
      })

      if (response.ok) {
        const data = await response.json()
        toast.success(`Game ${command} command sent`, {
          description: `Sent to ${data.results.length} servers`
        })
        fetchData(); // Update UI immediately
      } else {
        toast.error(`Failed to send ${command} command`)
      }
    } catch (error) {
      toast.error(`Error sending ${command} command`)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="container mx-auto py-10 space-y-8">
      {/* Game Management Section */}
      <Card>
        <CardHeader>
          <CardTitle>Game Management</CardTitle>
          <CardDescription>Upload builds and control game processes across all servers.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 md:grid-cols-2">
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
                <Progress value={uploadProgress} className="w-full h-2" />
              )}
            </div>

            <div className="space-y-4">
              <Label>Process Control (Broadcast All)</Label>
              <div className="flex gap-2">
                <Button
                  onClick={() => handleCommand("start")}
                  variant="default"
                  disabled={allRunning}
                >
                  <Play className="h-4 w-4 mr-2" /> Start All
                </Button>
                <Button
                  onClick={() => handleCommand("stop")}
                  variant="destructive"
                  disabled={allStopped}
                >
                  <Square className="h-4 w-4 mr-2" /> Stop All
                </Button>
              </div>
              <p className="text-sm text-muted-foreground">
                {allRunning ? "All servers are running." : allStopped ? "All servers are stopped." : "Mixed server states."}
              </p>
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
              <Button variant="outline" size="icon" onClick={fetchData} disabled={loading}>
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
                </TableRow>
              </TableHeader>
              <TableBody>
                {servers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-24 text-center">
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
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
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
