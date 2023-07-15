defmodule CA.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ca,
      version: "4.7.14",
      elixir: "~> 1.7",
      description: "CA  CXC 138 21 Certificate Authority",
      package: package(),
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(src priv lib mix.exs LICENSE),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ca,
      links: %{"GitHub" => "https://github.com/synrc/ca"}
    ]
  end

  def application(), do: [mod: {CA, []}, applications: [:ranch,:cowboy]]

  def deps() do
    [
      {:cowboy, "~> 2.5.0"},
      {:cowlib, "~> 2.6.0"},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
