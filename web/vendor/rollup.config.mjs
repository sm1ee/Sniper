import { nodeResolve } from "@rollup/plugin-node-resolve";
import terser from "@rollup/plugin-terser";

export default {
  input: "entry.js",
  output: {
    file: "../codemirror.bundle.js",
    format: "iife",
    name: "CM",
    sourcemap: false,
  },
  plugins: [
    nodeResolve(),
    terser({
      compress: { passes: 2 },
      mangle: true,
    }),
  ],
};
