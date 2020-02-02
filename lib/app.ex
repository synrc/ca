defmodule CA do
  use Application
  use Supervisor
  def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
  def start(_type, _args) do
    {:ok, _} = :cowboy.start_clear(:http,[{:port,8046}],%{env: %{dispatch: :ca_enroll.boot()}})
    :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
  end
end
