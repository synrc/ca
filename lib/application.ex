defmodule CA do
  @moduledoc """
  The main CA module implements Elixir application functionality
  that runs TCP and HTTP connections under Erlang/OTP supervision.
  """
  use Application
  def port(app) do Application.fetch_env!(:ca, app) end
  def start(_type, _args) do
      :logger.add_handlers(:ca)
      Supervisor.start_link([
         { Task.Supervisor, name: CA.TaskSupervisor},
         { CA.CMP,  port: port(:cmp) },
         { CA.CMC,  port: port(:cmc) },
         { CA.OCSP, port: port(:ocsp) },
         { CA.TSP,  port: port(:tsp) },
#        { CA.EUDI.Issuer, port: port(:issuer), plug: CA.EUDI.Issuer, scheme: :http, thousand_island_options: [num_acceptors: 1] },
#        { CA.EUDI.Verifier, port: port(:verifier), plug: CA.EUDI.Verifier, scheme: :http, thousand_island_options: [num_acceptors: 1] },
#        { CA.EUDI.Wallet, port: port(:wallet), plug: CA.EUDI.Wallet, scheme: :http, thousand_island_options: [num_acceptors: 1] },
         { CA.EST,  port: port(:est), plug: CA.EST, scheme: :http, thousand_island_options: [num_acceptors: 1] }
      ], strategy: :one_for_one, name: CA.Supervisor)
  end

end
