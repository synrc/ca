defmodule CA.Integer do
  import Bitwise

  def modulo(x, n), do: rem(x, n) |> correctNegativeModulo(n)
  def correctNegativeModulo(r, n) when r < 0, do: r + n
  def correctNegativeModulo(r, _n), do: r
  def ipow(base, p, acc \\ 1)
  def ipow(base, p, acc) when p > 0, do: ipow(base, p - 1, base * acc)
  def ipow(_base, _p, acc), do: acc

  def between(minimum, maximum) when minimum < maximum do
      range = maximum - minimum + 1
      {bytesNeeded, mask} = calculateParameters(range)
      randomNumber = :crypto.strong_rand_bytes(bytesNeeded)
                  |> :binary.bin_to_list()
                  |> bytesToNumber &&& mask

      if randomNumber < range do
         minimum + randomNumber
      else
         between(minimum, maximum)
      end
  end

  def bytesToNumber(randomBytes, randomNumber \\ 0, i \\ 0)
  def bytesToNumber([randomByte | otherRandomBytes], randomNumber, i), do:
      bytesToNumber(otherRandomBytes, randomNumber ||| randomByte <<< (8 * i), i + 1)
  def bytesToNumber([], randomNumber, _i), do: randomNumber

  def calculateParameters(range), do: calculateParameters(range, 1, 0)
  def calculateParameters(range, mask, bitsNeeded) when range > 0, do:
      calculateParameters(range >>> 1, mask <<< 1 ||| 1, bitsNeeded + 1)
  def calculateParameters(_range, mask, bitsNeeded), do: {div(bitsNeeded, 8) + 1, mask}

end
