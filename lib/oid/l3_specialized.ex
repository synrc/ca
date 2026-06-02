defmodule CA.L3.Specialized do
  @moduledoc "Level 3: Specialized Courts Security Profile"

  def controls do
    CA.L2.controls() ++
    [
      CA.SPE.oid(:"id-spe-au-2"),
      CA.SPE.oid(:"id-spe-sc-12"),
      CA.SPE.oid(:"id-spe-sc-7"),
      CA.SPE.oid(:"id-spe-sc-28")
    ]
  end
end
