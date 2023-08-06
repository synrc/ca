defmodule CA.Point do
  defstruct [:x, :y, z: 0]
  def isAtInfinity?(p) do
    p.y == 0
  end

end
