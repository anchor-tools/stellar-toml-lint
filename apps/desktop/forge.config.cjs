/**
 * Electron Forge packaging (issue #371).
 *
 * The three installers the issue asks for, each from the maker that produces
 * the format a user of that platform expects to double-click:
 *
 * - **macOS → DMG**, `@electron-forge/maker-dmg`. The disk image with a
 *   drag-to-Applications layout.
 * - **Windows → MSI**, `@electron-forge/maker-wix`. Chosen over the Squirrel
 *   maker Forge defaults to, because an MSI is what a corporate IT department
 *   can deploy by policy — and the people this app is for work at the kind of
 *   company that deploys software by policy. It needs the WiX Toolset v3 on the
 *   build machine; see README.md.
 * - **Linux → AppImage**, `@reforged/maker-appimage`. Forge ships no first-party
 *   AppImage maker (its Linux makers are deb, rpm, flatpak, and snap), so this
 *   is the community one. A single executable file needs no package manager and
 *   no root, which is the point of asking for AppImage rather than a .deb.
 *
 * A ZIP maker is included for every platform as well: it is what CI can build
 * and attach without any platform-specific toolchain installed, so a smoke test
 * of the packaging step does not require a signing identity or WiX.
 *
 * CommonJS (`.cjs`) because Forge loads this config with `require`, while the
 * app itself is ESM.
 */

/** @type {import('@electron-forge/shared-types').ForgeConfig} */
module.exports = {
  packagerConfig: {
    name: 'Stellar TOML Lint',
    executableName: 'stellar-toml-lint-desktop',
    appBundleId: 'tools.anchor.stellar-toml-lint',
    appCategoryType: 'public.app-category.developer-tools',
    // Everything the app actually ships. Without this, Forge packs the whole
    // directory including the Forge toolchain itself.
    ignore: [
      /^\/src\//,
      /^\/scripts\//,
      /^\/tsconfig\.json$/,
      /^\/forge\.config\.cjs$/,
      /^\/README\.md$/,
      /^\/\.gitignore$/,
    ],
    // Native modules are unpacked by the plugin below rather than being
    // loaded from inside the asar, which does not work for binaries.
    asar: true,
    // Set OSX_SIGN_IDENTITY in the environment to sign a release build;
    // unsigned builds still run locally, with a Gatekeeper prompt.
    ...(process.env.OSX_SIGN_IDENTITY
      ? { osxSign: { identity: process.env.OSX_SIGN_IDENTITY } }
      : {}),
  },

  plugins: [
    {
      name: '@electron-forge/plugin-auto-unpack-natives',
      config: {},
    },
  ],

  makers: [
    {
      name: '@electron-forge/maker-dmg',
      platforms: ['darwin'],
      config: {
        name: 'Stellar TOML Lint',
        format: 'ULFO',
      },
    },
    {
      name: '@electron-forge/maker-wix',
      platforms: ['win32'],
      config: {
        name: 'Stellar TOML Lint',
        manufacturer: 'anchor-tools',
        // A stable GUID is what lets an MSI *upgrade* rather than install a
        // second copy beside the first. Generated once; never regenerate it.
        upgradeCode: '4f0a2f38-6a31-5c4b-9d7e-2b8c1a6f3e94',
        shortName: 'StellarTomlLint',
        ui: { chooseDirectory: true },
      },
    },
    {
      name: '@reforged/maker-appimage',
      platforms: ['linux'],
      config: {
        options: {
          name: 'stellar-toml-lint-desktop',
          productName: 'Stellar TOML Lint',
          categories: ['Development', 'Utility'],
        },
      },
    },
    {
      // Toolchain-free fallback, so CI can exercise packaging on every platform.
      name: '@electron-forge/maker-zip',
      platforms: ['darwin', 'win32', 'linux'],
    },
  ],
};
