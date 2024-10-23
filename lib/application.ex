defmodule CA do
  @moduledoc """
  The main CA module mostly contains (except OTP application prelude)
  public_key and PKIXCMP HRL definitions. The latter are generated
  from PKIXCMP-2009.asn1 the ASN.1 specification of CMP protocol.
  """
  use Application
  use Supervisor

  require Record
  Enum.each(Record.extract_all(from_lib: "ca/include/PKIXCMP-2009.hrl"),
            fn {name, definition} -> Record.defrecord(name, definition) end)
  Enum.each(Record.extract_all(from_lib: "public_key/include/public_key.hrl"),
            fn {name, definition} -> Record.defrecord(name, definition) end)

  def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
  def start(_type, _args) do
      :logger.add_handlers(:ca)
      CA.CMP.start ; CA.CMC.start ; CA.TSP.start ; CA.OCSP.start
      :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
  end

end
