defmodule CA.L2 do
  @moduledoc "Level 2: Sectoral Security Profile"

  def controls do
    CA.L1.controls() ++
    [
      CA.SPE.oid(:"id-spe-ia-2-1"),
      CA.SPE.oid(:"id-spe-ia-2-2"),
      CA.SPE.oid(:"id-spe-sc-8-1")
    ]
  end
end
