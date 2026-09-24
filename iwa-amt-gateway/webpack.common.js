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

const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyPlugin = require('copy-webpack-plugin');
const webpack = require('webpack');
const packageJson = require('./package.json');

module.exports = {
  cache: false, // Disable webpack cache to always get fresh builds
  entry: {
    main: './app.js',
    'service-worker': './service-worker.js',
    loader: './loader.js',
    'mpegts-player': './mpegts-player.js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      },
      // No .html or .css rule: nothing in the entry graph imports either, and
      // HtmlWebpackPlugin compiles index.html itself. The .html rule used to
      // name html-loader, which was never in devDependencies, so it only ever
      // failed the child compilation (BLO-36052).
    ],
  },
  plugins: [
    // Inject version from package.json at build time
    new webpack.DefinePlugin({
      __APP_VERSION__: JSON.stringify(packageJson.version),
    }),
    new CopyPlugin({
      patterns: [
        { from: "icons", to: "icons", noErrorOnMissing: true },
        {
          from: ".well-known",
          to: ".well-known",
          transform(content, absoluteFrom) {
            // Inject version into manifest.webmanifest. This is the only
            // writer of that field: the source manifest's placeholder
            // "0.0.0" never ships.
            if (absoluteFrom.endsWith('manifest.webmanifest')) {
              const manifest = JSON.parse(content.toString());
              manifest.version = packageJson.version;
              return JSON.stringify(manifest, null, 2);
            }
            return content;
          }
        },
        { 
          from: "update_manifest.json", 
          to: "update_manifest.json", 
          noErrorOnMissing: true,
          transform(content) {
            // Inject version into update_manifest.json
            const updateManifest = JSON.parse(content.toString());
            if (updateManifest.versions && updateManifest.versions.length > 0) {
              updateManifest.versions[0].version = packageJson.version;
            }
            return JSON.stringify(updateManifest, null, 2);
          }
        },
        // Optional: cmd/wasm-client does not exist in this repo, so nothing
        // produces amt-client.wasm. app.js's fetch('amt-client.wasm') 404s at
        // runtime today; that is BLO-36052's sibling BLO-36170, not a build
        // problem. Drop noErrorOnMissing there — either once an entrypoint is
        // written, or by deleting this pattern if the WASM client is retired.
        { from: "amt-client.wasm", to: "amt-client.wasm", noErrorOnMissing: true },
        { from: "wasm_exec.js", to: "wasm_exec.js" },
        { from: "amt-url-parser.js", to: "amt-url-parser.js" },
        { from: "constants.js", to: "constants.js" },
        { from: "install-page.html", to: "install-page.html", noErrorOnMissing: true },
      ]
    }),
    new HtmlWebpackPlugin({
      filename: 'index.html',
      template: 'index.html',
      chunks: ['main', 'loader'],
      inject: 'body',
      scriptLoading: 'blocking',
      publicPath: '/'
    }),
  ],
  resolve: {
    extensions: [ '.js' ]
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    publicPath: '/',
    trustedTypes: {
      policyName: 'amt-gateway#webpack',
    }
  },
  optimization: {
    runtimeChunk: {
      name: entrypoint => entrypoint.name === 'service-worker' ? false : 'runtime'
    },
    splitChunks: {
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: (chunk) => chunk.name !== 'service-worker'
        }
      }
    }
  }
};

