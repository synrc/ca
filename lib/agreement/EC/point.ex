defmodule CA.Point do
  @moduledoc "CA Point library."
  defstruct [:x, :y, z: 0]
  def isAtInfinity?(p) do
    p.y == 0
  end

end
