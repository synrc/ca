defmodule CA.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ca,
      version: "1.1.0",
      elixir: "~> 1.7",
      description: "CA Certificate Authority",
      package: package(),
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

  def application() do
    [mod: {:ca, []}, applications: [:ranch,:cowboy]]
  end

  def deps() do
    [
      {:cowboy, "~> 2.7.0"},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
