/* eslint-disable @typescript-eslint/no-explicit-any */
declare module 'framer-motion';
declare module 'gsap';
declare module 'three/examples/jsm/controls/OrbitControls.js';

declare namespace JSX {
  interface IntrinsicElements {
    instancedMesh: any;
    lineSegments: any;
    color: any;
    fog: any;
    sphereGeometry: any;
    meshStandardMaterial: any;
    bufferGeometry: any;
    bufferAttribute: any;
    lineBasicMaterial: any;
    ambientLight: any;
    pointLight: any;
    perspectiveCamera: any;
    meshBasicMaterial: any;
    orbitControls: any;
    float: any;
    sphere: any;
    html: any;
  }
}
