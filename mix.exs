defmodule CA.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ca,
      version: "4.8.2",
      elixir: "~> 1.7",
      description: "CA  CXC 138 21 Certificate Authority",
      package: package(),
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(config src include priv lib mix.exs LICENSE README.md),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ca,
      links: %{"GitHub" => "https://github.com/synrc/ca"}
    ]
  end

  def application(), do: [mod: {CA, []}, applications: [:x509]]

  def deps() do
    [
      {:x509, "~> 0.8.7"},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
