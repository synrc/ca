defmodule CA.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :ca,
      version: "0.8.0",
      elixir: "~> 1.7",
      description: "CA Certificate Authority",
      package: package(),
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(doc src mix.exs LICENSE),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :ca,
      links: %{"GitHub" => "https://github.com/synrc/ca"}
    ]
  end

  def application() do
    [mod: {:ca, []}]
  end

  def deps() do
    [
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
