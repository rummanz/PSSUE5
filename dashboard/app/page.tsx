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
      const response = await fetch("http://localhost:90/api/status")
      if (response.ok) {
        const data: StatusResponse = await response.json()
        setServers(data.servers)
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

  const fetchVersions = async () => {
    try {
      toast("Checking versions...");
      const response = await fetch("http://localhost:90/api/game/version");
      if (response.ok) {
        const data = await response.json();
        // In a real app we would merge this into the 'servers' state based on IP
        // seeing as the broadcast returns results keyed by IP
        toast("Version check complete", { description: JSON.stringify(data.results) });
      }
    } catch (error) {
      toast.error("Failed to check version");
    }
  }

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

      const response = await axios.post("http://localhost:90/api/game/upload", formData, {
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
      toast.error("Error during upload")
      console.error(error)
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }

  const handleCommand = async (command: "start" | "stop") => {
    try {
      const response = await fetch("http://localhost:90/api/game/broadcast", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command }),
      })

      if (response.ok) {
        const data = await response.json()
        toast.success(`Game ${command} command sent`, {
          description: `Sent to ${data.results.length} servers`
        })
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
              <Label>Process Control</Label>
              <div className="flex gap-2">
                <Button onClick={() => handleCommand("start")} variant="default">
                  <Play className="h-4 w-4 mr-2" /> Start Game
                </Button>
                <Button onClick={() => handleCommand("stop")} variant="destructive">
                  <Square className="h-4 w-4 mr-2" /> Stop Game
                </Button>
                <Button onClick={fetchVersions} variant="outline">
                  <Info className="h-4 w-4 mr-2" /> Check Versions
                </Button>
              </div>
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
                  <TableHead>Last Ping</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {servers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="h-24 text-center">
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
                        {new Date(server.lastPingReceived).toLocaleTimeString()}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* Stats Cards */}
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
