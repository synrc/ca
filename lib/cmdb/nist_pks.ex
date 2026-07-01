defmodule CA.NIST.PrivateKeyStorage do
  @moduledoc "NIST SP 800-53 controls for Private Key Storage"
  def controls do
    [
      CA.SPE.oid(:"id-spe-sc-12"),    # Cryptographic Key Establishment and Management
      CA.SPE.oid(:"id-spe-sc-12-4"),  # Cryptographic Key Storage (encryption at rest)
      CA.SPE.oid(:"id-spe-sc-12-5"),  # Cryptographic Key Destruction
      CA.SPE.oid(:"id-spe-sc-13"),    # Cryptographic Protection (FIPS-validated)
      CA.SPE.oid(:"id-spe-sc-28"),    # Protection of Information at Rest
      CA.SPE.oid(:"id-spe-sc-28-1"),  # Cryptographic Protection at Rest
      CA.SPE.oid(:"id-spe-mp-4"),     # Media Storage
      CA.SPE.oid(:"id-spe-mp-6")      # Media Sanitization
    ]
  end
end
