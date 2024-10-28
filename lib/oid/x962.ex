defmodule CA.X962 do
  @moduledoc "CA ANSI X.962 OIDs."
  def oid(:"id-ft-prime-field"),                          do: {1, 2, 840, 10045, 1, 1}
  def oid(:"id-ft-characteristic-two-field"),             do: {1, 2, 840, 10045, 1, 2}
  def oid(:"id-kt-ecPublicKey"),                          do: {1, 2, 840, 10045, 2, 1}
  def oid(:"id-ct-characteristicTwo"),                    do: {1, 2, 840, 10045, 3, 0}
  def oid(:"id-ct-prime"),                                do: {1, 2, 840, 10045, 3, 1}
  def oid(:"id-ds-ecdsa-with-SHA1"),                      do: {1, 2, 840, 10045, 4, 1}
  def oid(:"id-ds-ecdsa-with-Recommended"),               do: {1, 2, 840, 10045, 4, 2}
  def oid(:"id-ds-ecdsa-with-SHA2"),                      do: {1, 2, 840, 10045, 4, 3}
  def oid(:"id-ds-ecdsa-with-SHA224"),                    do: {1, 2, 840, 10045, 4, 3, 1}
  def oid(:"id-ds-ecdsa-with-SHA256"),                    do: {1, 2, 840, 10045, 4, 3, 2}
  def oid(:"id-ds-ecdsa-with-SHA384"),                    do: {1, 2, 840, 10045, 4, 3, 3}
  def oid(:"id-ds-ecdsa-with-SHA512"),                    do: {1, 2, 840, 10045, 4, 3, 4}
end