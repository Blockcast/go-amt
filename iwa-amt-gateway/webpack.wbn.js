/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const { merge } = require('webpack-merge');
const common = require('./webpack.common.js');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const WebBundlePlugin = require('webbundle-webpack-plugin');
const { WebBundleId, parsePemKey, NodeCryptoSigningStrategy } = require('wbn-sign');
const fs = require("fs");
require('dotenv').config({ path: '.env' });

const privateKeyFile = process.env.KEYFILE || "private.pem";
let privateKey;
if (process.env.KEY) {
  privateKey = process.env.KEY;
} else if (fs.existsSync(privateKeyFile)) {
  privateKey = fs.readFileSync(privateKeyFile);
}

// Custom CSP that allows localhost connections for dev/testing
const customCSP = "base-uri 'none'; default-src 'self'; object-src 'none'; " +
  "frame-src 'self' https: blob: data:; " +
  "connect-src 'self' http://localhost:* https: wss: blob: data:; " +
  "script-src 'self' 'wasm-unsafe-eval'; " +
  "img-src 'self' https: blob: data:; " +
  "media-src 'self' https: blob: data:; " +
  "font-src 'self' blob: data:; " +
  "style-src 'self' 'unsafe-inline'; " +
  "require-trusted-types-for 'script'; " +
  "frame-ancestors 'self';";

let webBundlePlugin;
if (privateKey) {
  const parsedPrivateKey = parsePemKey(privateKey);

  webBundlePlugin = new WebBundlePlugin({
    baseURL: new WebBundleId(
      parsedPrivateKey
    ).serializeWithIsolatedWebAppOrigin(),
    output: 'amt-gateway.swbn',
    integrityBlockSign: {
      strategy: new NodeCryptoSigningStrategy(parsedPrivateKey)
    },
    headerOverride: {
      'content-security-policy': customCSP,
      'cross-origin-embedder-policy': 'require-corp',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
    },
  });
} else {
  webBundlePlugin = new WebBundlePlugin({
    baseURL: '/',
    output: 'amt-gateway.wbn',
    headerOverride: {
      'content-security-policy': customCSP,
    },
  });
}

module.exports = merge(common, {
  mode: 'production',
  plugins: [
    new CleanWebpackPlugin({
      cleanOnceBeforeBuildPatterns: ['**/*', '!amt-gateway.swbn']
    }),
    webBundlePlugin,
  ]
});

