import '@testing-library/jest-dom/vitest'
import { vi } from 'vitest'
import { createElement } from 'react'

vi.mock('recharts', () => {
  const chart = (props: Record<string, unknown>) => {
    const { children, ...rest } = props
    return createElement('div', { 'data-testid': 'recharts-mock', ...rest }, children)
  }
  return {
    ResponsiveContainer: chart,
    LineChart: chart,
    BarChart: chart,
    PieChart: chart,
    AreaChart: chart,
    ComposedChart: chart,
    Line: () => null,
    Bar: () => null,
    Pie: () => null,
    Area: () => null,
    XAxis: () => null,
    YAxis: () => null,
    CartesianGrid: () => null,
    Tooltip: () => null,
    Legend: () => null,
    Cell: () => null,
    ReferenceLine: () => null,
    ReferenceArea: () => null,
  }
})

vi.mock('three', () => ({
  WebGLRenderer: vi.fn(),
  Scene: vi.fn(),
  PerspectiveCamera: vi.fn(),
  AmbientLight: vi.fn(),
  DirectionalLight: vi.fn(),
  Mesh: vi.fn(),
  BoxGeometry: vi.fn(),
  MeshStandardMaterial: vi.fn(),
  Vector3: vi.fn(() => ({ x: 0, y: 0, z: 0, set: vi.fn(), copy: vi.fn() })),
  Euler: vi.fn(() => ({ x: 0, y: 0, z: 0 })),
  Color: vi.fn(() => ({ r: 0, g: 0, b: 0 })),
  Clock: vi.fn(() => ({ getDelta: vi.fn(() => 0), getElapsedTime: vi.fn(() => 0) })),
  BufferAttribute: vi.fn(),
  Float32BufferAttribute: vi.fn(),
  Group: vi.fn(),
  Object3D: vi.fn(() => ({ add: vi.fn(), remove: vi.fn(), position: { x: 0, y: 0, z: 0 }, rotation: { x: 0, y: 0, z: 0 } })),
  TextureLoader: vi.fn(() => ({ load: vi.fn() })),
  LinearFilter: 0,
  sRGBEncoding: 0,
  ACESFilmicToneMapping: 0,
  NoToneMapping: 0,
}))

vi.mock('@react-three/fiber', () => ({
  Canvas: ({ children }: { children: React.ReactNode }) => createElement('div', { 'data-testid': 'r3f-canvas' }, children),
  useFrame: vi.fn(),
  useThree: vi.fn(() => ({ gl: {}, scene: {}, camera: {} })),
}))

vi.mock('@react-three/drei', () => ({
  OrbitControls: () => null,
  Text: ({ children }: { children: React.ReactNode }) => createElement('span', null, children),
  Environment: () => null,
  Float: ({ children }: { children: React.ReactNode }) => children,
  Stars: () => null,
}))

vi.mock('@react-three/postprocessing', () => ({
  EffectComposer: ({ children }: { children: React.ReactNode }) => children,
  Bloom: () => null,
}))

vi.mock('gsap', () => ({
  gsap: {
    to: vi.fn(),
    from: vi.fn(),
    fromTo: vi.fn(),
    timeline: vi.fn(() => ({ to: vi.fn(), from: vi.fn(), play: vi.fn() })),
    set: vi.fn(),
    killTweensOf: vi.fn(),
  },
  ScrollTrigger: { create: vi.fn() },
}))

vi.mock('d3-force', () => ({
  forceSimulation: vi.fn(() => ({ force: vi.fn().mockReturnThis(), on: vi.fn().mockReturnThis(), stop: vi.fn(), start: vi.fn() })),
  forceLink: vi.fn(() => ({ id: vi.fn().mockReturnThis(), distance: vi.fn().mockReturnThis() })),
  forceManyBody: vi.fn(() => ({ strength: vi.fn().mockReturnThis() })),
  forceCenter: vi.fn(() => ({ x: 0, y: 0 })),
  forceCollide: vi.fn(),
}))

vi.mock('d3-scale', () => ({
  scaleLinear: vi.fn(() => Object.assign(vi.fn(), { domain: vi.fn().mockReturnThis(), range: vi.fn().mockReturnThis() })),
  scaleOrdinal: vi.fn(() => Object.assign(vi.fn(), { domain: vi.fn().mockReturnThis(), range: vi.fn().mockReturnThis() })),
  scaleTime: vi.fn(() => Object.assign(vi.fn(), { domain: vi.fn().mockReturnThis(), range: vi.fn().mockReturnThis() })),
}))

vi.mock('d3-shape', () => ({
  line: vi.fn(() => Object.assign(vi.fn(), { x: vi.fn().mockReturnThis(), y: vi.fn().mockReturnThis() })),
  area: vi.fn(() => Object.assign(vi.fn(), { x: vi.fn().mockReturnThis(), y0: vi.fn().mockReturnThis(), y1: vi.fn().mockReturnThis() })),
  arc: vi.fn(() => Object.assign(vi.fn(), { innerRadius: vi.fn().mockReturnThis(), outerRadius: vi.fn().mockReturnThis() })),
  pie: vi.fn(() => Object.assign(vi.fn(), { value: vi.fn().mockReturnThis(), sort: vi.fn().mockReturnThis() })),
}))

vi.mock('d3-array', () => ({
  range: vi.fn(() => []),
  max: vi.fn(() => 0),
  min: vi.fn(() => 0),
  extent: vi.fn(() => [0, 0]),
  mean: vi.fn(() => 0),
  sum: vi.fn(() => 0),
}))
