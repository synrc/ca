defmodule CA.L3.Local do
  @moduledoc "Level 3: Local Courts Security Profile"

  def controls do
    CA.L2.controls() ++
    [
      CA.SPE.oid(:"id-spe-pe-3")
    ]
  end
end
