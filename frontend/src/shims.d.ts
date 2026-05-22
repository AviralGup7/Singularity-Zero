/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import React from 'react';

declare module 'react' {
  namespace JSX {
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
}
