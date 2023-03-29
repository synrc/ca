defmodule CA.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ca,
      version: "3.3.0",
      elixir: "~> 1.7",
#      compilers: [:asn1] ++ Mix.compilers,
      description: "CA Certificate Authority",
      package: package(),
#      asn1_paths: ["priv/kep"],
#      erlc_paths: ["src"],
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(src lib mix.exs LICENSE),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ca,
      links: %{"GitHub" => "https://github.com/synrc/ca"}
    ]
  end

  def application(), do: [mod: {CA, []}, applications: [:ranch,:cowboy]]

  def deps() do
    [
      {:cowboy, "~> 2.7.0"},
#      {:asn1ex, "~> 0.0.1", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
