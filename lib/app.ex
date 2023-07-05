defmodule CA do
  use Application
  use Supervisor
  def apps() do
      :lists.filter(fn {x,_,_} when
            x == :n2o or x == :chat or x == :bpe or x== :ca or
            x == :ns or x == :kvs or x == :ldap or
            x == :inets or x == :compiler or x == :stdlib or
            x == :kernel or x == :mnesia or x == :crypto  -> true
                _ -> false end, :application.which_applications) end
  def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
  def port(), do: :application.get_env(:ca, :port, 8046)
  def start(_type, _args) do
    {:ok, _} = :cowboy.start_clear(:http,[{:port,port()}],%{env: %{dispatch: :ca_enroll.boot()}})
    :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
  end
end
