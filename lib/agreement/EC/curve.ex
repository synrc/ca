defmodule CA.Curve do
  @moduledoc false
  require CA.Integer
  require CA.Point
  defstruct [:A, :B, :P, :N, :G, :name, :oid]
  def contains?(curve, p) do
      cond do
        p.x < 0 || p.x > curve."P" - 1 -> false
        p.y < 0 || p.y > curve."P" - 1 -> false
        CA.Integer.ipow(p.y, 2) - (CA.Integer.ipow(p.x, 3) + curve."A" * p.x + curve."B")
          |> CA.Integer.modulo(curve."P") != 0 -> false
        true -> true
      end
  end
  def getLength(curve) do
      div(1 + String.length(Integer.to_string(curve."N", 16)), 2)
  end
end
