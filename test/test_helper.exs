backend = System.get_env("KVS_BACKEND", "mnesia")

excludes =
  case backend do
    "rocksdb" -> [:mnesia]
    "mnesia" -> [:rocksdb]
    _ -> []
  end

openssl_cmp_available? =
  case System.find_executable("openssl") do
    nil ->
      false

    openssl ->
      case System.cmd(openssl, ["list", "-commands"], stderr_to_stdout: true) do
        {commands, 0} ->
          commands
          |> String.split()
          |> Enum.member?("cmp")

        _ ->
          false
      end
  end

excludes =
  if openssl_cmp_available? do
    excludes
  else
    IO.puts("OpenSSL CMP command is unavailable; excluding :openssl_cmp integration tests")
    [:openssl_cmp | excludes]
  end

ExUnit.start(exclude: excludes)
