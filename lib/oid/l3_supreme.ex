defmodule CA.L3.Supreme do
  @moduledoc "Level 3: Supreme Courts Security Profile"

  def controls do
    CA.L2.Court.controls() ++
      [
        CA.SPE.oid(:"id-spe-cp-2"),
        CA.SPE.oid(:"id-spe-cp-10"),
        CA.SPE.oid(:"id-spe-sc-6")
      ]
  end
end
