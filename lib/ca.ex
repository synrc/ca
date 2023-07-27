defmodule CA do
  use Application
  use Supervisor
  require Record
  Enum.each(Record.extract_all(from_lib: "ca/include/PKIXCMP-2009.hrl"),
            fn {name, definition} -> Record.defrecord(name, definition) end)
  def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
  def port(), do: :application.get_env(:ca, :port, 8046)
  def start(_type, _args) do
#     {:ok, _} = :cowboy.start_clear(:http,[{:port,port()}],%{env: %{dispatch: :ca_enroll.boot()}})
      :logger.add_handlers(:ldap)
      CA.CMP.start
      :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
  end
end
