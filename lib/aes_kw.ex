defmodule CA.AES.KW do
   def wrap(x, y), do: :aes_kw.wrap(x, y)
   def unwrap(x, y), do: :aes_kw.unwrap(x, y)
end
