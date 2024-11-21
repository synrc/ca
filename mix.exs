defmodule CA.Mixfile do
  use Mix.Project
  def application(), do: [ mod: {CA, []}, extra_applications: [:x509, :bandit, :plug, :logger]]
  def project() do
    [
      app: :ca,
      version: "5.11.15",
      description: "CA  CXC 138 21 Certificate Authority",
      package: [
        name: :ca,
        files: ~w(config src include priv lib mix.exs LICENSE README.md),
        licenses: ["ISC"],
        maintainers: ["Namdak Tonpa"],
        links: %{"GitHub" => "https://github.com/synrc/ca"}
      ],
      deps: [
        {:base85, "~> 0.2.0"},
        {:cose, "~> 0.11.20"},
        {:jason, "~> 1.2"},
        {:plug, "~> 1.15.3"},
        {:bandit, "~> 1.0"},
        {:ex_doc, ">= 0.0.0", only: :dev},
        {:x509, "~> 0.8.7"}
      ]
    ]
  end
end
