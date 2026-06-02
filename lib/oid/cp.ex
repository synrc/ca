defmodule CA.CP do
  @moduledoc "CA Certificate Policies OIDs for Ukraine Court Systems."

  def oid(:"id-cp-ua-court-basic"),           do: {1, 2, 804, 3, 1, 2, 1}
  def oid(:"id-cp-ua-court-branch"),          do: {1, 2, 804, 3, 1, 2, 2}
  def oid(:"id-cp-ua-court-supreme"),         do: {1, 2, 804, 3, 1, 2, 3, 1}
  def oid(:"id-cp-ua-court-anti-corruption"), do: {1, 2, 804, 3, 1, 2, 3, 2}
  def oid(:"id-cp-ua-court-ip"),              do: {1, 2, 804, 3, 1, 2, 3, 3}
  def oid(:"id-cp-ua-court-general"),         do: {1, 2, 804, 3, 1, 2, 3, 4}

  def lookup({1, 2, 804, 3, 1, 2, 1}), do: "Базовий профіль безпеки"
  def lookup({1, 2, 804, 3, 1, 2, 2}), do: "Галузевий профіль безпеки"
  def lookup({1, 2, 804, 3, 1, 2, 3, 1}), do: "Профіль безпеки Верховного Суду"
  def lookup({1, 2, 804, 3, 1, 2, 3, 2}), do: "Профіль безпеки Вищого антикорупційного суду"
  def lookup({1, 2, 804, 3, 1, 2, 3, 3}), do: "Профіль безпеки Вищого суду з питань інтелектуальної власності"
  def lookup({1, 2, 804, 3, 1, 2, 3, 4}), do: "Профіль безпеки загальних судів"
end
