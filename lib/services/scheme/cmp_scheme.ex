defmodule CA.CMP.Scheme do
  @moduledoc """
  """
  require Record

  Enum.each(Record.extract_all(from_lib: "ca/include/PKIXCMP-2009.hrl"),
            fn {name, definition} -> Record.defrecord(name, definition) end)
end
