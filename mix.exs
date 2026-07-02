defmodule CA.Mixfile do
  use Mix.Project
  def application(), do: [mod: {CA, []}, extra_applications: [:x509, :bandit, :plug, :logger]]
  def project() do
    [
      app: :ca,
      version: "7.6.3",
      description: "CA  CXC 138 21 Certificate Authority",
      releases: [ca: [include_executables_for: [:unix], cookie: "SYNRC:CA"]],
      package: [
        name: :ca,
        files: ~w(config src include priv lib c_src mix.exs LICENSE README.md),
        licenses: ["ISC"],
        maintainers: ["Namdak Tonpa"],
        links: %{"GitHub" => "https://github.com/synrc/ca"}
      ],
      compilers: [:nif_make] ++ Mix.compilers(),
      deps: [
        {:base85, "~> 1.1.0"},
        {:cose, "~> 0.11.20"},
        {:jason, "~> 1.4.5"},
        {:plug, "~> 1.19.4"},
        {:bandit, "~> 1.11.1"},
        {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
        {:x509, "~> 0.9.0"}
      ]
    ]
  end
end

defmodule Mix.Tasks.Compile.NifMake do
  use Mix.Task.Compiler
  @shortdoc "Apple (SEP) Secure Enclave Processor (macOS) / TPM (Linux)"
  @impl true
  def run(_args) do
    os = :os.type()
    supported = match?({:unix, :darwin}, os) or match?({:unix, :linux}, os)
    if supported do
      {result, exit_code} = System.cmd("make", ["-C", "c_src"], stderr_to_stdout: true)
      if exit_code == 0 do
        Mix.shell().info([:green, "* NIF make: ", :reset, String.trim(result)])
        {:ok, []}
      else
        Mix.shell().error("NIF make failed:\n#{result}")
        {:error, []}
      end
    else
      {:ok, []}
    end
  end
  @impl true
  def clean do
    _ = System.cmd("make", ["-C", "c_src", "clean"], stderr_to_stdout: true)
    :ok
  end
end
