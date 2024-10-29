defmodule CA.X962 do # ALSO newer ANSI X9.142–2020 ECDSA for 1.3.132.0 curves
  @moduledoc "CA ANSI X.962 OIDs."
  def oid(:"id-ft-prime-field"),                          do: {1, 2, 840, 10045, 1, 1}
  def oid(:"id-ft-characteristic-two-field"),             do: {1, 2, 840, 10045, 1, 2}
  def oid(:"id-kt-ecPublicKey"),                          do: {1, 2, 840, 10045, 2, 1}
  def oid(:"id-ct-characteristicTwo"),                    do: {1, 2, 840, 10045, 3, 0}
  def oid(:"id-ct-prime"),                                do: {1, 2, 840, 10045, 3, 1}
  def oid(:ansiX9p192r1),                                 do: {1, 2, 840, 10045, 3, 1, 1}
  def oid(:secp192r1),                                    do: {1, 2, 840, 10045, 3, 1, 1}
  def oid(:prime192v1),                                   do: {1, 2, 840, 10045, 3, 1, 1}
  def oid(:prime192v2),                                   do: {1, 2, 840, 10045, 3, 1, 2}
  def oid(:prime192v3),                                   do: {1, 2, 840, 10045, 3, 1, 3}
  def oid(:prime239v1),                                   do: {1, 2, 840, 10045, 3, 1, 4}
  def oid(:prime239v2),                                   do: {1, 2, 840, 10045, 3, 1, 5}
  def oid(:prime239v3),                                   do: {1, 2, 840, 10045, 3, 1, 6}
  def oid(:secp256r1),                                    do: {1, 2, 840, 10045, 3, 1, 7}
  def oid(:prime256v1),                                   do: {1, 2, 840, 10045, 3, 1, 7}
  def oid(:sect163k1),                                    do: {1, 3, 132, 0, 1}
  def oid(:sect163r2),                                    do: {1, 3, 132, 0, 15}
  def oid(:secp224r1),                                    do: {1, 3, 132, 0, 33}
  def oid(:sect233k1),                                    do: {1, 3, 132, 0, 26}
  def oid(:sect233r1),                                    do: {1, 3, 132, 0, 27}
  def oid(:sect283k1),                                    do: {1, 3, 132, 0, 16}
  def oid(:sect283r1),                                    do: {1, 3, 132, 0, 17}
  def oid(:secp384r1),                                    do: {1, 3, 132, 0, 34}
  def oid(:sect409k1),                                    do: {1, 3, 132, 0, 36}
  def oid(:sect409r1),                                    do: {1, 3, 132, 0, 37}
  def oid(:secp521r1),                                    do: {1, 3, 132, 0, 35}
  def oid(:sect571k1),                                    do: {1, 3, 132, 0, 38}
  def oid(:sect571r1),                                    do: {1, 3, 132, 0, 39}
  def oid(:"id-ds-ecdsa-with-SHA1"),                      do: {1, 2, 840, 10045, 4, 1}
  def oid(:"id-ds-ecdsa-with-Recommended"),               do: {1, 2, 840, 10045, 4, 2}
  def oid(:"id-ds-ecdsa-with-SHA2"),                      do: {1, 2, 840, 10045, 4, 3}
  def oid(:"id-ds-ecdsa-with-SHA224"),                    do: {1, 2, 840, 10045, 4, 3, 1}
  def oid(:"id-ds-ecdsa-with-SHA256"),                    do: {1, 2, 840, 10045, 4, 3, 2}
  def oid(:"id-ds-ecdsa-with-SHA384"),                    do: {1, 2, 840, 10045, 4, 3, 3}
  def oid(:"id-ds-ecdsa-with-SHA512"),                    do: {1, 2, 840, 10045, 4, 3, 4}
end