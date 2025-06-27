const resolve = require('@rollup/plugin-node-resolve').default;
const commonjs = require('@rollup/plugin-commonjs');
const { terser } = require('rollup-plugin-terser');

module.exports = {
  // Entry point: il tuo loader principale
  input: 'webkit.js',
  plugins: [
    resolve(),   // risolve import da node_modules e da src
    commonjs(),  // converte moduli CommonJS in ES6
    terser()     // minimizza il bundle per produzione
  ],
  output: {
    // File di output
    file: 'dist/bundle.js',
    // Formato IIFE per includerlo come <script> classico
    format: 'iife',
    // Namespace globale: tutto sarà disponibile sotto window.PSFreeExploit
    name: 'PSFreeExploit',
    sourcemap: true
  }
};