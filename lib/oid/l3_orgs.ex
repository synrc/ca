defmodule CA.L3.Orgs do
  @moduledoc "Level 3: Judicial Organizations Security Profile"

  def controls do
    CA.L2.controls() ++
    [
      CA.SPE.oid(:"id-spe-ac-5"),
      CA.SPE.oid(:"id-spe-sc-8-2")
    ]
  end
end
