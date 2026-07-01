defmodule CA.Test.OpenSSL do
  @moduledoc false

  def executable do
    System.get_env("OPENSSL3") ||
      System.get_env("OPENSSL") ||
      System.find_executable("openssl") ||
      "openssl"
  end

  def cmd(args, opts \\ []) do
    System.cmd(executable(), args, Keyword.put(opts, :env, command_env()))
  end

  def cmp_available? do
    case cmd(["list", "-commands"], stderr_to_stdout: true) do
      {commands, 0} ->
        commands
        |> String.split()
        |> Enum.member?("cmp")

      _ ->
        false
    end
  end

  defp command_env do
    library_paths = openssl_library_paths()

    case library_paths do
      [] ->
        []

      paths ->
        current = System.get_env("LD_LIBRARY_PATH", "")
        value = Enum.join(paths ++ nonempty(current), ":")
        [{"LD_LIBRARY_PATH", value}]
    end
  end

  defp openssl_library_paths do
    prefix =
      executable()
      |> Path.expand()
      |> Path.dirname()
      |> Path.dirname()

    [Path.join(prefix, "lib64"), Path.join(prefix, "lib")]
    |> Enum.filter(&File.dir?/1)
  end

  defp nonempty(""), do: []
  defp nonempty(value), do: [value]
end

backend = System.get_env("KVS_BACKEND", "mnesia")

excludes =
  case backend do
    "rocksdb" -> [:mnesia]
    "mnesia" -> [:rocksdb]
    _ -> []
  end

excludes =
  if CA.Test.OpenSSL.cmp_available?() do
    excludes
  else
    IO.puts("OpenSSL CMP command is unavailable; excluding :openssl_cmp integration tests")
    [:openssl_cmp | excludes]
  end

ExUnit.start(exclude: excludes)
