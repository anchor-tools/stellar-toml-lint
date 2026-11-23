class StellarTomlLint < Formula
  desc "Offline SEP-1 linter for stellar.toml"
  homepage "https://github.com/anchor-tools/stellar-toml-lint"
  url "https://github.com/anchor-tools/stellar-toml-lint/releases/download/v#{version}/stellar-toml-lint.tar.gz"
  sha256 :no_check
  license "Apache-2.0"
  head "https://github.com/anchor-tools/stellar-toml-lint.git", branch: "main"

  depends_on "node"

  def install
    system "npm", "install"
    system "npm", "run", "build"
    bin.install "dist/cli.js" => "stellar-toml-lint"
  end

  test do
    system "#{bin}/stellar-toml-lint", "--version"
  end
end
