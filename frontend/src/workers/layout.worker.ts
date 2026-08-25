/**
 * Off-main-thread force-directed layout for the 3D cockpit graph.
 * Post { type: 'layout', nodes: {id,x,y}[], edges: {source,target}[] }.
 */
export type LayoutNode = { id: string; x: number; y: number }
export type LayoutEdge = { source: string; target: string }

function tick(nodes: LayoutNode[], edges: LayoutEdge[], iterations = 40): LayoutNode[] {
  const pos = nodes.map((n) => ({ ...n }))
  const idx = new Map(pos.map((n, i) => [n.id, i]))
  for (let iter = 0; iter < iterations; iter++) {
    for (let i = 0; i < pos.length; i++) {
      for (let j = i + 1; j < pos.length; j++) {
        const dx = pos[j].x - pos[i].x || 0.01
        const dy = pos[j].y - pos[i].y || 0.01
        const dist = Math.hypot(dx, dy) || 0.01
        const force = 80 / (dist * dist)
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        pos[i].x -= fx
        pos[i].y -= fy
        pos[j].x += fx
        pos[j].y += fy
      }
    }
    for (const e of edges) {
      const a = idx.get(e.source)
      const b = idx.get(e.target)
      if (a === undefined || b === undefined) continue
      const dx = pos[b].x - pos[a].x
      const dy = pos[b].y - pos[a].y
      pos[a].x += dx * 0.05
      pos[a].y += dy * 0.05
      pos[b].x -= dx * 0.05
      pos[b].y -= dy * 0.05
    }
  }
  return pos
}

self.onmessage = (ev: MessageEvent) => {
  const data = ev.data
  if (!data || data.type !== 'layout') return
  const nodes = Array.isArray(data.nodes) ? data.nodes : []
  const edges = Array.isArray(data.edges) ? data.edges : []
  const result = tick(nodes, edges, Number(data.iterations) || 40)
  ;(self as unknown as Worker).postMessage({ type: 'layout-result', nodes: result })
}
