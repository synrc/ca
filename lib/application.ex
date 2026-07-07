defmodule CA do
  @moduledoc """
  The main CA module implements Elixir application functionality
  that runs TCP and HTTP connections under Erlang/OTP supervision.
  """
  use Application

  def port(app) do
    Application.fetch_env!(:ca, app)
  end

  def start(_type, _args) do
    :logger.add_handlers(:ca)

    # Detect and persist the active key backend so all modules use the same one
    backend = {:software, "synrc/ecc/secp384r1/se/ca.key"}
    Application.put_env(:ca, :key_backend, backend)
    :logger.info(~c"CA KEY BACKEND: ~p", [backend])

    # Initialize CA key material for all configured curve profiles
    profiles = Application.get_env(:ca, :profiles, ["secp384r1"])
    Enum.each(profiles, fn profile ->
      :logger.info(~c"CA INIT PROFILE: ~p", [profile])
      CA.CSR.init(profile)
    end)

    Supervisor.start_link(
      [
        {Task.Supervisor, name: CA.TaskSupervisor},
        {CA.CMP, port: port(:cmp)},
        {CA.CMC, port: port(:cmc)},
        {CA.OCSP, port: port(:ocsp)},
        {CA.TSP, port: port(:tsp)},
        #        { CA.EUDI.Issuer, port: port(:issuer), plug: CA.EUDI.Issuer, scheme: :http, thousand_island_options: [num_acceptors: 1] },
        #        { CA.EUDI.Verifier, port: port(:verifier), plug: CA.EUDI.Verifier, scheme: :http, thousand_island_options: [num_acceptors: 1] },
        #        { CA.EUDI.Wallet, port: port(:wallet), plug: CA.EUDI.Wallet, scheme: :http, thousand_island_options: [num_acceptors: 1] },
        {CA.EST, port: port(:est), plug: CA.EST, scheme: :http, thousand_island_options: [num_acceptors: 1]}
      ], strategy: :one_for_one, name: CA.Supervisor)
  end


end
