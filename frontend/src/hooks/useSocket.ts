import { useEffect, useRef, useState } from 'react'
import { io, Socket } from 'socket.io-client'

const API_ORIGIN = import.meta.env.VITE_API_ORIGIN ?? 'http://localhost:5000'

export interface ThreatEvent {
  flow_id: string
  source_ip: string
  destination_ip: string
  attack_type: string
  confidence: number
  risk_score: number
  risk_level: string
  protocol: string
  port: number
  timestamp: string
}

export interface ActionEvent {
  action_type: string
  target: string
  severity_level: string
  success: boolean
  details: string
  timestamp: string
}

export interface MetricsUpdate {
  total_flows: number
  threats_detected: number
  avg_confidence: number
  avg_risk_score: number
  high_risk_count: number
  critical_count: number
}

export function useSocket(
  orgId: number,
  onNewThreat?: (threat: ThreatEvent) => void
) {
  const socketRef = useRef<Socket | null>(null)
  const onNewThreatRef = useRef(onNewThreat)
  const [connected, setConnected] = useState(false)
  const [threats, setThreats] = useState<ThreatEvent[]>([])
  const [actions, setActions] = useState<ActionEvent[]>([])
  const [metrics, setMetrics] = useState<MetricsUpdate | null>(null)

  // Keep callback ref fresh without re-subscribing socket
  useEffect(() => {
    onNewThreatRef.current = onNewThreat
  }, [onNewThreat])

  useEffect(() => {
    const socket = io(API_ORIGIN, {
      withCredentials: true,
      transports: ['websocket', 'polling'],
    })
    socketRef.current = socket

    socket.on('connect', () => {
      setConnected(true)
      socket.emit('subscribe_predictions', { org_id: orgId })
      socket.emit('request_metrics', { org_id: orgId })
    })

    socket.on('disconnect', () => setConnected(false))
    socket.on('connect_error', () => setConnected(false))

    socket.on('prediction', (data: ThreatEvent) => {
      setThreats(prev => [data, ...prev].slice(0, 50))
      onNewThreatRef.current?.(data)
    })

    socket.on('action_taken', (data: { action: ActionEvent }) => {
      setActions(prev => [data.action, ...prev].slice(0, 30))
    })

    socket.on('metrics_update', (data: { metrics: MetricsUpdate }) => {
      setMetrics(data.metrics)
    })

    return () => {
      socket.disconnect()
    }
  }, [orgId])

  return { connected, threats, actions, metrics }
}
