defmodule CA do
  @moduledoc """
  The main CA module implements Elixir application functionality
  that runs TCP and HTTP connections under Erlang/OTP supervision.
  """
  use Application
  def start(_type, _args) do
      :logger.add_handlers(:ca)
      Supervisor.start_link([
         { CA.CMP, port: Application.fetch_env!(:ca, :cmp) },
         { CA.EST, port: Application.fetch_env!(:ca, :est), plug: CA.EST, scheme: :http, thousand_island_options: [num_acceptors: 1] }
      ], strategy: :one_for_one, name: CA.Supervisor)
  end

end
