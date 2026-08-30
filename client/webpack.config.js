const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');
const path = require('path');

module.exports = {
    mode: 'development',
    // Webpack's development default uses eval(), which is incompatible with
    // Mailtrain's Content-Security-Policy. Keep readable development output
    // without requiring the unsafe-eval CSP escape hatch.
    devtool: false,
    entry: {
        "root": ['./src/root.js'],
        "mosaico-root": ['./src/lib/sandboxed-mosaico-root.js'],
        "ckeditor-root": ['./src/lib/sandboxed-ckeditor-root.js'],
        "grapesjs-root": ['./src/lib/sandboxed-grapesjs-root.js'],
        "codeeditor-root": ['./src/lib/sandboxed-codeeditor-root.js'],
    },
    output: {
        library: 'MailtrainReactBody',
        filename: '[name].js',
        path: path.resolve(__dirname, 'dist'),
        hashFunction: 'sha256'
    },
    resolve: {
        fallback: {
            fs: false,
            http: false,
            https: false,
            os: false,
            path: require.resolve('path-browserify'),
            url: require.resolve('url/')
        }
    },
    module: {
        rules: [
            {
                test: /\.m?js$/,
                resolve: {
                    fullySpecified: false
                }
            },
            {
                test: /\.(js|jsx)$/,
                exclude: path.join(__dirname, 'node_modules'),
                use: [
                    {
                        loader: 'babel-loader',
                        options: {
                            presets: [
                                ['@babel/preset-env', {
                                    loose: true,
                                    targets: {
                                        "chrome": "58",
                                        "edge": "15",
                                        "firefox": "55",
                                        "ios": "10"
                                    }
                                }],
                                '@babel/preset-react'
                            ],
                            plugins: [
                                ["@babel/plugin-proposal-decorators", { "legacy": true }],
                                ["@babel/plugin-proposal-class-properties", { "loose" : true }],
                                "@babel/plugin-proposal-function-bind"
                            ]
                        }
                    }
                ]
            },
            {
                test: /\.css$/,
                use: [
                    {
                        loader: 'style-loader'
                    },
                    {
                        loader: 'css-loader'
                    }
                ]
            },
            {
                test: /\.(png|jpg|gif)$/,
                type: 'asset',
                parser: {
                    dataUrlCondition: {
                        maxSize: 8192
                    }
                }
            },
            {
                test: /\.scss$/,
                exclude: path.join(__dirname, 'node_modules'),
                use: [
                    'style-loader',
                    {
                        loader: 'css-loader',
                        options: {
                            modules: {
                                localIdentName: '[path][name]__[local]--[hash:base64:5]'
                            }
                        }
                    },
                    'sass-loader'
                ]
            },
            {
                test: /\.(svg|otf|woff2|woff|ttf|eot)$/,
                type: 'asset'
            }
        ]
    },
    externals: {
        jquery: 'jQuery',
        csrfToken: 'csrfToken',
        mailtrainConfig: 'mailtrainConfig'
    },
    plugins: [
      new webpack.ProvidePlugin({
        process: 'process/browser'
      }),
      new CopyPlugin({
        patterns: [
          { from: './node_modules/jquery/dist/jquery.min.js', to: path.resolve(__dirname, 'dist') },
          { from: './node_modules/popper.js/dist/umd/popper.min.js', to: path.resolve(__dirname, 'dist') },
          { from: './node_modules/bootstrap/dist/js/bootstrap.min.js', to: path.resolve(__dirname, 'dist') },
          { from: './node_modules/@coreui/coreui/dist/js/coreui.min.js', to: path.resolve(__dirname, 'dist') },
          { from: './node_modules/@fortawesome/fontawesome-free/webfonts/', to: path.resolve(__dirname, 'dist', 'webfonts') }
        ]
      }),
    ],
    watchOptions: {
        ignored: 'node_modules/',
        poll: 2000
    }
};
