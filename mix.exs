defmodule CA.Mixfile do
  use Mix.Project
  def application(), do: [ mod: {CA, []}, applications: [:x509]]
  def project() do
    [
      app: :ca,
      version: "5.10.1",
      description: "CA  CXC 138 21 Certificate Authority",
      package: [
        name: :ca,
        files: ~w(config src include priv lib mix.exs LICENSE README.md),
        licenses: ["ISC"],
        maintainers: ["Namdak Tonpa"],
        links: %{"GitHub" => "https://github.com/synrc/ca"}
      ],
      deps: [
        {:ex_doc, ">= 0.0.0", only: :dev},
        {:x509, "~> 0.8.7"}
      ]
    ]
  end
end
