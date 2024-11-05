defmodule CA.Jacobian do
  @moduledoc "CA Jacobian library."
  require CA.Integer
  require CA.Point

  def toJacobian(p), do: %CA.Point{x: p.x, y: p.y, z: 1}
  def fromJacobian(p, cP) do
      z = inv(p.z, cP)
      %CA.Point{
        x: CA.Integer.modulo(p.x * CA.Integer.ipow(z, 2), cP),
        y: CA.Integer.modulo(p.y * CA.Integer.ipow(z, 3), cP)
      }
  end

  def multiply(p, n, cN, cA, cP), do:
      p |> toJacobian()
        |> jacobianMultiply(n, cN, cA, cP)
        |> fromJacobian(cP)
  def add(p, q, cA, cP), do:
      jacobianAdd(toJacobian(p), toJacobian(q), cA, cP)
        |> fromJacobian(cP)
  def inv(x, _) when x == 0, do: 0
  def inv(x, n), do:
      invOperator(1, 0, CA.Integer.modulo(x, n), n)
        |> CA.Integer.modulo(n)
  def invOperator(lm, hm, low, high) when low > 1 do
      r = div(high, low)
      invOperator(hm - lm * r, lm, high - low * r, low) end
  def invOperator(lm, _, _, _), do: lm

  def jacobianDouble(p, cA, cP) do
      if p.y == 0 do
         %CA.Point{x: 0, y: 0, z: 0}
      else
        ysq = CA.Integer.ipow(p.y, 2) |> CA.Integer.modulo(cP)
        s = (4 * p.x * ysq) |> CA.Integer.modulo(cP)
        m = (3 * CA.Integer.ipow(p.x, 2) + cA * CA.Integer.ipow(p.z, 4)) |> CA.Integer.modulo(cP)
        nx = (CA.Integer.ipow(m, 2) - 2 * s) |> CA.Integer.modulo(cP)
        ny = (m * (s - nx) - 8 * CA.Integer.ipow(ysq, 2)) |> CA.Integer.modulo(cP)
        nz = (2 * p.y * p.z) |> CA.Integer.modulo(cP)
        %CA.Point{x: nx, y: ny, z: nz}
      end
  end

  def jacobianAdd(p, q, cA, cP) do
      if p.y == 0 do
         q
      else
         if q.y == 0 do
            p
         else
           u1 = (p.x * CA.Integer.ipow(q.z, 2)) |> CA.Integer.modulo(cP)
           u2 = (q.x * CA.Integer.ipow(p.z, 2)) |> CA.Integer.modulo(cP)
           s1 = (p.y * CA.Integer.ipow(q.z, 3)) |> CA.Integer.modulo(cP)
           s2 = (q.y * CA.Integer.ipow(p.z, 3)) |> CA.Integer.modulo(cP)

           if u1 == u2 do
             if s1 != s2 do
                %CA.Point{x: 0, y: 0, z: 1}
             else
               jacobianDouble(p, cA, cP)
             end
           else
             h = u2 - u1
             r = s2 - s1
             h2 = (h * h) |> CA.Integer.modulo(cP)
             h3 = (h * h2) |> CA.Integer.modulo(cP)
             u1h2 = (u1 * h2) |> CA.Integer.modulo(cP)
             nx = (CA.Integer.ipow(r, 2) - h3 - 2 * u1h2) |> CA.Integer.modulo(cP)
             ny = (r * (u1h2 - nx) - s1 * h3) |> CA.Integer.modulo(cP)
             nz = (h * p.z * q.z) |> CA.Integer.modulo(cP)
             %CA.Point{x: nx, y: ny, z: nz}
           end
         end
       end
  end

  def jacobianMultiply(_p, n, _cN, _cA, _cP) when n == 0, do: %CA.Point{x: 0, y: 0, z: 1}
  def jacobianMultiply(p, n, _cN, _cA, _cP) when n == 1 do
      case p.y do
           0 -> %CA.Point{x: 0, y: 0, z: 1}
           _ -> p
      end
  end
  def jacobianMultiply(p, n, cN, cA, cP) when n < 0 or n >= cN do
      case p.y do
           0 -> %CA.Point{x: 0, y: 0, z: 1}
           _ -> jacobianMultiply(p, CA.Integer.modulo(n, cN), cN, cA, cP)
      end
  end
  def jacobianMultiply(p, _n, _cN, _cA, _cP) when p.y == 0, do: %CA.Point{x: 0, y: 0, z: 1}
  def jacobianMultiply(p, n, cN, cA, cP) when rem(n, 2) == 0 do
      jacobianMultiply(p, div(n, 2), cN, cA, cP) |> jacobianDouble(cA, cP)
  end
  def jacobianMultiply(p, n, cN, cA, cP) do
      jacobianMultiply(p, div(n, 2), cN, cA, cP) |> jacobianDouble(cA, cP) |> jacobianAdd(p, cA, cP)
  end

end
